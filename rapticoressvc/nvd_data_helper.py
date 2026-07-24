import json
import logging
import time
from datetime import datetime, timedelta

import requests
from rapticoressvc.config import get_config
from rapticoressvc.multi_threading_helper import run_parallel
from rapticoressvc.storage_helpers.files_helper import read_from_json_file
from rapticoressvc.storage_helpers.files_helper import save_to_json_file
from rapticoressvc.storage_helpers.redis_helper import redis_read_json
from rapticoressvc.storage_helpers.redis_helper import redis_write_json
from rapticoressvc.storage_helpers.s3_helper import download_data_from_s3
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.storage_helpers.s3_helper import upload_data_to_s3
from rapticoressvc.svcc_constants import STORAGE_LOCAL
from rapticoressvc.svcc_constants import STORAGE_REDIS
from rapticoressvc.svcc_constants import STORAGE_S3

# NVD 2.0 REST API. The legacy JSON 1.1 yearly data feeds were retired by NIST in
# December 2023 and are no longer updated, so data is now fetched on demand per CVE.
# All tunables (base URL, timeout, retries, TTL, concurrency, API key) come from
# the centralized config (rapticoressvc.config), which loads them from env.
CVE_NVD_DATA_DIRECTORY = "cve_nvd_data"

# Rejected CVE records reference their replacements; cap how deep we follow them.
MAX_REFERENCE_LOOKUPS = 3


def update_nvd_data():
    """No-op retained for CLI/Lambda compatibility.

    NVD data is now fetched on demand per CVE from the NVD 2.0 API (see
    get_nvd_data) rather than bulk-downloaded from the retired 1.1 yearly feeds.
    """
    logging.info('NVD data is fetched on-demand per CVE from the NVD 2.0 API; '
                 'no bulk update required.')


def _now_iso():
    return datetime.now().isoformat()


def _cache_file_destination(bucket_name, cve):
    return [bucket_name, CVE_NVD_DATA_DIRECTORY, f'{cve}.json']


def _read_cached_record(cve, args):
    bucket_name = args.get("bucket_name")
    storage_type = args.get("storage_type", "")
    try:
        if storage_type == STORAGE_S3:
            s3_client = args.get("s3_client")
            cve_key = f"{CVE_NVD_DATA_DIRECTORY}/{cve}"
            return download_data_from_s3(s3_client, bucket_name, cve_key)
        elif storage_type == STORAGE_LOCAL:
            return read_from_json_file(_cache_file_destination(bucket_name, cve))
        elif storage_type == STORAGE_REDIS:
            return redis_read_json(_cache_file_destination(bucket_name, cve))
    except Exception as e:
        logging.exception(e)
    return None


def _write_cached_record(cve, record, args):
    bucket_name = args.get("bucket_name")
    storage_type = args.get("storage_type", "")
    upload_status = False
    try:
        if storage_type == STORAGE_S3:
            s3_client = args.get("s3_client")
            cve_key = f"{CVE_NVD_DATA_DIRECTORY}/{cve}"
            upload_status = upload_data_to_s3(s3_client, bucket_name, cve_key, record)
        elif storage_type == STORAGE_LOCAL:
            upload_status = save_to_json_file(record, _cache_file_destination(bucket_name, cve))
        elif storage_type == STORAGE_REDIS:
            # Redis-native expiry backstops the retrieved_at freshness check.
            ttl_seconds = get_config().nvd_cache_ttl_hours * 3600
            upload_status = redis_write_json(record, _cache_file_destination(bucket_name, cve),
                                             ttl_seconds=ttl_seconds)
    except Exception as e:
        logging.exception(e)
    return upload_status


def _is_fresh(record):
    """A cached record is fresh if it carries a retrieved_at within the TTL.

    Old-format records (from the legacy 1.1 loader) have no retrieved_at and are
    therefore treated as stale, so they get transparently refreshed on first use.
    """
    retrieved_at = record.get("retrieved_at") if isinstance(record, dict) else None
    if not retrieved_at:
        return False
    try:
        retrieved_dt = datetime.fromisoformat(retrieved_at)
        ttl_hours = get_config().nvd_cache_ttl_hours
        return datetime.now() - retrieved_dt < timedelta(hours=ttl_hours)
    except Exception:
        return False


def _pick_cvss(entries):
    if not entries:
        return None, None
    primary = [e for e in entries if e.get("type") == "Primary"]
    chosen = (primary or entries)[0]
    cvss_data = chosen.get("cvssData", {}) or {}
    return cvss_data.get("vectorString"), cvss_data.get("baseScore")


def _select_cvss(metrics):
    """Choose a CVSS vector/score, preferring newer base metric versions.

    Order: v3.1 > v3.0 > v4.0 > v2. The SSVC vectors (exposure via base score,
    utility via AV/UI) are computed the same way across versions.
    """
    metrics = metrics or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        vector, score = _pick_cvss(metrics.get(key))
        if vector:
            return vector, score, key
    return None, None, None


def _english_description(cve_obj):
    descriptions = cve_obj.get("descriptions", []) or []
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value")
    return descriptions[0].get("value") if descriptions else None


def normalize_nvd_2_cve(cve_obj):
    """Map an NVD 2.0 `cve` object to the internal cache/record format.

    The returned record preserves the keys the rest of the codebase relies on
    (`cve_vector`, `cve_score`) and exposes a flat `description`, plus provenance
    fields and the raw 2.0 object under `nvd_data`.
    """
    vector, score, cvss_version = _select_cvss(cve_obj.get("metrics", {}))
    return {
        "cve_id": cve_obj.get("id"),
        "cve_vector": vector,
        "cve_score": score,
        "cvss_version": cvss_version,
        "description": _english_description(cve_obj),
        "vuln_status": cve_obj.get("vulnStatus"),
        "last_modified_date": cve_obj.get("lastModified"),
        "retrieved_at": _now_iso(),
        "nvd_data": json.dumps(cve_obj),
    }


def _backoff_seconds(attempt, response=None):
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return min(30, int(retry_after))
            except (TypeError, ValueError):
                pass
    # NVD suggests ~6s between requests when unauthenticated/throttled.
    return min(30, 6 * (attempt + 1))


def fetch_nvd_cve_from_api(cve):
    """Fetch a single CVE's `cve` object from the NVD 2.0 API.

    Returns the raw 2.0 `cve` dict, or None if the CVE is unknown or the request
    fails after retries. Honors an optional NVD_API_KEY for higher rate limits.
    """
    config = get_config()
    headers = {}
    if config.nvd_api_key:
        headers["apiKey"] = config.nvd_api_key
    url = f"{config.nvd_api_base_url}?cveId={cve}"

    for attempt in range(config.nvd_max_retries):
        try:
            logging.debug(f"Fetching NVD 2.0 record for {cve} (attempt {attempt + 1})")
            response = requests.get(url, headers=headers, timeout=config.nvd_api_timeout)
            if response.status_code == 200:
                vulnerabilities = response.json().get("vulnerabilities") or []
                if not vulnerabilities:
                    logging.warning(f"NVD 2.0 returned no record for {cve}")
                    return None
                return vulnerabilities[0].get("cve")
            if response.status_code in (403, 429):
                wait = _backoff_seconds(attempt, response)
                logging.warning(f"NVD 2.0 rate-limited ({response.status_code}) for {cve}; "
                                f"retrying in {wait}s")
                time.sleep(wait)
                continue
            if response.status_code == 404:
                logging.warning(f"NVD 2.0 has no record for {cve} (404)")
                return None
            logging.warning(f"NVD 2.0 returned status {response.status_code} for {cve}")
            return None
        except Exception as e:
            logging.warning(f"Error fetching NVD 2.0 record for {cve}: {e}")
            time.sleep(_backoff_seconds(attempt))
    logging.error(f"Giving up fetching NVD 2.0 record for {cve} after {config.nvd_max_retries} attempts")
    return None


def _is_rejected(record):
    if not isinstance(record, dict):
        return "** REJECT **" in str(record)
    if str(record.get("vuln_status")).lower() == "rejected":
        return True
    return "** REJECT **" in str(record.get("description") or "")


def get_referenced_cves_from_nvd_record(rejected_nvd_record):
    """Extract replacement CVE IDs referenced by a rejected CVE's description."""
    referenced_cves = []
    try:
        if isinstance(rejected_nvd_record, dict):
            description = str(rejected_nvd_record.get("description") or "")
        else:
            description = str(rejected_nvd_record or "")
        cves = None
        if "All CVE users should reference" in description:
            cves = description.split("All CVE users should reference")[1].split(".")[0]
        elif "All CVE users should consult" in description:
            cves = description.split("All CVE users should consult")[1].split(".")[0]
        elif "use CVE-" in description:
            cves = "CVE-" + description.split("use CVE-")[1].split(".")[0]
        if cves is not None:
            cves = [segment.strip(",[]") for segment in cves.split(" ")
                    if segment.startswith("CVE-") or segment.startswith("[CVE-")]
            [referenced_cves.append(cve) for cve in cves if cve not in referenced_cves]
    except Exception as e:
        logging.exception(e)
    return referenced_cves


def fetch_and_cache_nvd_record(cve, args):
    cve_obj = fetch_nvd_cve_from_api(cve)
    if cve_obj is None:
        return None
    record = normalize_nvd_2_cve(cve_obj)
    _write_cached_record(cve, record, args)
    return record


def download_nvd_record(cve, args):
    """Resolve one CVE to its normalized record: cache first, then NVD 2.0 API.

    Rejected records are followed to their replacement CVE(s) up to
    MAX_REFERENCE_LOOKUPS deep. On a fetch failure a stale cached record, if any,
    is returned rather than nothing.
    """
    logging.debug(f'Getting NVD data for CVE: {cve}')
    recursion_level = args.get("recursion_level", 1)
    try:
        cached = _read_cached_record(cve, args)
        if cached and _is_fresh(cached):
            record = cached
        else:
            record = fetch_and_cache_nvd_record(cve, args)
            if record is None:
                record = cached  # fall back to stale cache when the fetch fails

        if not record:
            return {cve: None}

        if _is_rejected(record):
            if recursion_level <= MAX_REFERENCE_LOOKUPS:
                referenced_cves = get_referenced_cves_from_nvd_record(record)
                if referenced_cves:
                    return get_nvd_data(referenced_cves, recursion_level=recursion_level + 1)
            return {cve: None}

        return {cve: record}
    except Exception as e:
        logging.exception(e)
    return {cve: None}


def get_nvd_data(cves, max_workers=None, recursion_level=1):
    cve_nvd_map = {}
    config = get_config()
    bucket_name = config.bucket_name
    storage_type = config.storage_type
    max_workers = max_workers or config.nvd_max_workers
    allowed_storage_medium = [STORAGE_S3, STORAGE_LOCAL, STORAGE_REDIS]
    if not bucket_name or not storage_type or storage_type not in allowed_storage_medium:
        logging.error(f'Missing or incorrect configuration, bucket_name: {bucket_name}, '
                      f'storage_type: {storage_type}')
        return cve_nvd_map
    try:
        cves = cves if type(cves) is list else [cves]
        s3_client = storage_type == STORAGE_S3 and get_s3_client()
        args = dict(bucket_name=bucket_name, s3_client=s3_client, storage_type=storage_type,
                    recursion_level=recursion_level)
        cve_nvd_list = run_parallel(download_nvd_record, cves, args, max_workers)
        cve_nvd_map = dict((key, cve_nvd_dict[key]) for cve_nvd_dict in cve_nvd_list for key in cve_nvd_dict)
    except Exception as e:
        logging.exception(e)
    return cve_nvd_map

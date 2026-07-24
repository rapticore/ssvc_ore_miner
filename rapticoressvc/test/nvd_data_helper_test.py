import os

import fakeredis
from moto import mock_s3
from rapticoressvc import config
from rapticoressvc import nvd_data_helper
from rapticoressvc.nvd_data_helper import download_nvd_record
from rapticoressvc.nvd_data_helper import get_nvd_data
from rapticoressvc.nvd_data_helper import normalize_nvd_2_cve
from rapticoressvc.storage_helpers import redis_helper
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.svcc_constants import STORAGE_REDIS
from rapticoressvc.svcc_constants import STORAGE_S3
from rapticoressvc.test.testing_helper import make_nvd_2_cve


def _ensure_bucket():
    bucket_name, storage_type, region = os.environ.get("BUCKET_NAME"), os.environ.get("STORAGE_TYPE"), \
                                        os.environ.get("REGION")
    if storage_type == "s3":
        get_s3_client().create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
    return bucket_name, storage_type


def _args(bucket_name, storage_type, **extra):
    s3_client = storage_type == STORAGE_S3 and get_s3_client()
    return dict(bucket_name=bucket_name, s3_client=s3_client, storage_type=storage_type, **extra)


def test_normalize_nvd_2_cve_maps_core_fields():
    cve_obj = make_nvd_2_cve("CVE-2024-0001", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                             score=9.8, description="a serious bug")
    record = normalize_nvd_2_cve(cve_obj)
    assert record["cve_id"] == "CVE-2024-0001"
    assert record["cve_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert record["cve_score"] == 9.8
    assert record["cvss_version"] == "cvssMetricV31"
    assert record["description"] == "a serious bug"
    assert record["retrieved_at"]


def test_select_cvss_prefers_v31_over_v2():
    cve_obj = make_nvd_2_cve("CVE-2024-0002")
    cve_obj["metrics"]["cvssMetricV2"] = [{
        "type": "Primary", "cvssData": {"vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "baseScore": 9.3}}]
    record = normalize_nvd_2_cve(cve_obj)
    assert record["cvss_version"] == "cvssMetricV31"
    assert record["cve_score"] == 10.0


@mock_s3
def test_on_demand_fetch_and_cache(mocker):
    bucket_name, storage_type = _ensure_bucket()
    cve = "CVE-2025-1234"
    cve_obj = make_nvd_2_cve(cve, score=7.5)
    fetch = mocker.patch.object(nvd_data_helper, 'fetch_nvd_cve_from_api', return_value=cve_obj)

    # First lookup: cache miss -> hits the (mocked) API and caches the record.
    result = get_nvd_data([cve])
    assert result[cve]["cve_score"] == 7.5
    assert result[cve]["cve_vector"].startswith("CVSS:3.1/")
    assert fetch.call_count == 1

    # Second lookup: fresh cache -> no additional API call.
    result2 = get_nvd_data([cve])
    assert result2[cve]["cve_score"] == 7.5
    assert fetch.call_count == 1


@mock_s3
def test_unknown_cve_returns_none(mocker):
    _ensure_bucket()
    mocker.patch.object(nvd_data_helper, 'fetch_nvd_cve_from_api', return_value=None)
    result = get_nvd_data(["CVE-1900-0000"])
    assert result.get("CVE-1900-0000") is None


@mock_s3
def test_rejected_cve_follows_reference(mocker):
    bucket_name, storage_type = _ensure_bucket()
    rejected = make_nvd_2_cve(
        "CVE-2023-0001", vector=None, score=None, vuln_status="Rejected",
        description="** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. "
                    "ConsultIDs: none. Reason: withdrawn. Notes: use CVE-2023-9999 instead.")
    replacement = make_nvd_2_cve("CVE-2023-9999", score=8.1)

    def _fetch(cve):
        return {"CVE-2023-0001": rejected, "CVE-2023-9999": replacement}.get(cve)

    mocker.patch.object(nvd_data_helper, 'fetch_nvd_cve_from_api', side_effect=_fetch)

    result = download_nvd_record("CVE-2023-0001", _args(bucket_name, storage_type, recursion_level=1))
    # The rejected CVE resolves to its replacement's record.
    assert result.get("CVE-2023-9999") is not None
    assert result["CVE-2023-9999"]["cve_score"] == 8.1


def test_redis_backend_fetch_and_cache(mocker):
    # Inject a fake Redis and switch the active config to the redis backend.
    redis_helper._redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    config.configure(storage_type=STORAGE_REDIS, bucket_name="ssvc")
    try:
        cve = "CVE-2025-9999"
        cve_obj = make_nvd_2_cve(cve, score=6.6)
        fetch = mocker.patch.object(nvd_data_helper, 'fetch_nvd_cve_from_api', return_value=cve_obj)

        # Cache miss -> fetch + write to Redis.
        result = get_nvd_data([cve])
        assert result[cve]["cve_score"] == 6.6
        assert fetch.call_count == 1

        # Second lookup served from Redis, no extra fetch.
        result2 = get_nvd_data([cve])
        assert result2[cve]["cve_score"] == 6.6
        assert fetch.call_count == 1

        # The record really is in Redis under the namespaced key.
        assert redis_helper._redis_client.get("ssvc:cve_nvd_data:CVE-2025-9999") is not None
    finally:
        redis_helper._redis_client = None

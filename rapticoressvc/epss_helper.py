import json
import logging
import os
import requests
from datetime import datetime, timedelta
from rapticoressvc.storage_helpers.files_helper import read_from_json_file
from rapticoressvc.storage_helpers.files_helper import save_to_json_file
from rapticoressvc.storage_helpers.s3_helper import download_data_from_s3
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.storage_helpers.s3_helper import upload_data_to_s3
from rapticoressvc.svcc_constants import STORAGE_LOCAL
from rapticoressvc.svcc_constants import STORAGE_S3

EPSS_DATA_DIRECTORY = "epss_data"
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"
EPSS_CACHE_DURATION_HOURS = 24


def get_epss_local_data(bucket_name, epss_file_name, storage_type):
    """Get EPSS data from local storage or S3"""
    data = {}
    try:
        if storage_type == STORAGE_S3:
            s3_client = get_s3_client()
            epss_file_key = f"{EPSS_DATA_DIRECTORY}/{epss_file_name}"
            data = download_data_from_s3(s3_client, bucket_name, epss_file_key)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, EPSS_DATA_DIRECTORY, f'{epss_file_name}.json']
            data = read_from_json_file(file_destination)
        data = data or {}
    except Exception as e:
        logging.exception(e)
    return data


def update_epss_local_data(bucket_name, epss_file_name, data, storage_type):
    """Update EPSS data to local storage or S3"""
    try:
        upload_status = False
        if storage_type == STORAGE_S3:
            s3_client = get_s3_client()
            epss_file_key = f"{EPSS_DATA_DIRECTORY}/{epss_file_name}"
            upload_status = upload_data_to_s3(s3_client, bucket_name, epss_file_key, data)
        elif storage_type == STORAGE_LOCAL:
            file_destination = [bucket_name, EPSS_DATA_DIRECTORY, f'{epss_file_name}.json']
            upload_status = save_to_json_file(data, file_destination)
        logging.debug(f"EPSS data upload status: {upload_status}")
    except Exception as e:
        logging.exception(e)


def fetch_epss_scores(cves):
    """Fetch EPSS scores for given CVEs from FIRST.org API"""
    epss_scores = {}
    
    try:
        # EPSS API expects comma-separated CVEs
        cve_list = ','.join(cves)
        url = f"{EPSS_API_BASE_URL}?cve={cve_list}"
        
        logging.debug(f"Fetching EPSS scores for {len(cves)} CVEs")
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                for item in data['data']:
                    cve_id = item.get('cve')
                    epss_score = item.get('epss')
                    percentile = item.get('percentile')
                    if cve_id and epss_score is not None:
                        epss_scores[cve_id] = {
                            'epss_score': float(epss_score),
                            'percentile': float(percentile) if percentile else None,
                            'last_updated': datetime.now().isoformat()
                        }
        else:
            logging.warning(f"EPSS API returned status code: {response.status_code}")
            
    except Exception as e:
        logging.exception(f"Error fetching EPSS scores: {e}")
    
    return epss_scores


def get_epss_score(cve):
    """Get EPSS score for a single CVE"""
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    
    if not bucket_name or not storage_type:
        logging.error(f'Missing configuration for EPSS: bucket_name: {bucket_name}, storage_type: {storage_type}')
        return None
    
    try:
        file_name = "epss_scores"
        stored_data = get_epss_local_data(bucket_name, file_name, storage_type) or {}
        
        # Check if we have cached data for this CVE
        epss_scores = stored_data.get("epss_scores", {})
        last_update = stored_data.get("last_update")
        
        # Check if cache is still valid
        if last_update:
            last_update_dt = datetime.fromisoformat(last_update)
            if datetime.now() - last_update_dt < timedelta(hours=EPSS_CACHE_DURATION_HOURS):
                return epss_scores.get(cve)
        
        # Cache expired or CVE not found, fetch fresh data
        fresh_scores = fetch_epss_scores([cve])
        if fresh_scores:
            # Update cache with new data
            epss_scores.update(fresh_scores)
            stored_data.update({
                'epss_scores': epss_scores,
                'last_update': datetime.now().isoformat()
            })
            update_epss_local_data(bucket_name, file_name, stored_data, storage_type)
            return fresh_scores.get(cve)
        
    except Exception as e:
        logging.exception(f"Error getting EPSS score for {cve}: {e}")
    
    return None


def get_epss_scores_batch(cves):
    """Get EPSS scores for multiple CVEs efficiently"""
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    
    if not bucket_name or not storage_type:
        logging.error(f'Missing configuration for EPSS: bucket_name: {bucket_name}, storage_type: {storage_type}')
        return {}
    
    try:
        file_name = "epss_scores"
        stored_data = get_epss_local_data(bucket_name, file_name, storage_type) or {}
        
        epss_scores = stored_data.get("epss_scores", {})
        last_update = stored_data.get("last_update")
        
        # Check cache validity
        cache_valid = False
        if last_update:
            last_update_dt = datetime.fromisoformat(last_update)
            cache_valid = datetime.now() - last_update_dt < timedelta(hours=EPSS_CACHE_DURATION_HOURS)
        
        # Find CVEs not in cache or cache expired
        missing_cves = []
        if not cache_valid:
            missing_cves = cves
        else:
            missing_cves = [cve for cve in cves if cve not in epss_scores]
        
        # Fetch missing CVEs
        if missing_cves:
            fresh_scores = fetch_epss_scores(missing_cves)
            if fresh_scores:
                epss_scores.update(fresh_scores)
                stored_data.update({
                    'epss_scores': epss_scores,
                    'last_update': datetime.now().isoformat()
                })
                update_epss_local_data(bucket_name, file_name, stored_data, storage_type)
        
        # Return scores for requested CVEs
        return {cve: epss_scores.get(cve) for cve in cves}
        
    except Exception as e:
        logging.exception(f"Error getting EPSS scores batch: {e}")
    
    return {}


def update_epss_data():
    """Update EPSS data cache"""
    logging.info('Updating EPSS data...')
    bucket_name = os.environ.get("BUCKET_NAME")
    storage_type = os.environ.get("STORAGE_TYPE", "")
    
    if not bucket_name or not storage_type:
        logging.error(f'Missing configuration for EPSS: bucket_name: {bucket_name}, storage_type: {storage_type}')
        return
    
    try:
        # For now, we'll update on-demand when CVEs are requested
        # In the future, we could implement a full EPSS data sync here
        logging.info('EPSS data will be updated on-demand when CVEs are requested')
        
    except Exception as e:
        logging.exception(f"Error updating EPSS data: {e}")


def categorize_epss_score(epss_score):
    """Categorize EPSS score into risk levels"""
    if epss_score is None:
        return "unknown"
    elif epss_score >= 0.7:
        return "very_high"
    elif epss_score >= 0.5:
        return "high"
    elif epss_score >= 0.3:
        return "medium"
    elif epss_score >= 0.1:
        return "low"
    else:
        return "very_low" 
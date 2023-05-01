import json
import os

import pandas
from rapticoressvc.kevc_helper import get_kevc_cisa_data
from rapticoressvc.nvd_data_helper import get_nvd_data
from rapticoressvc.storage_helpers.files_helper import save_to_json_file
from rapticoressvc.svcc_constants import BUCKET_NAME
from rapticoressvc.svcc_constants import STORAGE_S3

os.environ["BUCKET_NAME"] = BUCKET_NAME
os.environ["STORAGE_TYPE"] = STORAGE_S3
os.environ["AWS_PROFILE"] = "dev1"  # be logged in to aws profile through sso
os.environ["AWS_REGION"] = "us-west-2"

"""
Generate NVD data for CVEs mentioned in sample_vulnerabilities_data.csv
"""


def get_test_cves(test_file_destination):
    excel_data_df = pandas.read_csv(test_file_destination)
    cve_numbers_list = list(excel_data_df.get("cve_number", []))
    cve_numbers = [cve.strip() for cve_numbers in cve_numbers_list for cve in cve_numbers.split('|')]
    cve_numbers = list(dict.fromkeys(cve_numbers)) or []
    return cve_numbers


def generate_sample_vulnerabilities_cve_nvd_data(test_file_destination, nvd_data_destination):
    cve_numbers = get_test_cves(test_file_destination)
    cve_details = cve_numbers and get_nvd_data(cve_numbers) or {}
    cve_nvd_data = [json.loads(data.get("nvd_data")) for data in list(cve_details.values()) if data]
    save_to_json_file(cve_nvd_data, nvd_data_destination)

# generate_sample_vulnerabilities_cve_nvd_data("./sample_vulnerabilities_data.csv",
#                                              [".", "sample_vulnerabilities_cve_nvd_data.json"])


"""
Generate kevc_cisa_data.json
"""


def generate_kevc_cisa_data(kevc_data_destination):
    kevc_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data, last_modified = get_kevc_cisa_data(kevc_url)
    kevc_data = {'last_modified': last_modified, 'data': data}
    save_to_json_file(kevc_data, kevc_data_destination)


# generate_kevc_cisa_data([".", "kevc_cisa_data.json"])

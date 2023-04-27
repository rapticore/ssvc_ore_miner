import json
import os

import pandas
from rapticoressvc.nvd_data_helper import get_nvd_data
from rapticoressvc.storage_helpers.files_helper import save_to_json_file
from rapticoressvc.svcc_constants import BUCKET_NAME
from rapticoressvc.svcc_constants import STORAGE_S3

os.environ["BUCKET_NAME"] = BUCKET_NAME
os.environ["STORAGE_TYPE"] = STORAGE_S3
os.environ["AWS_PROFILE"] = "dev1"  # be logged in to aws profile through sso
os.environ["AWS_REGION"] = "us-west-2"


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


# Generate fresh NVD data for CVEs in sample_vulnerabilities_data.csv
# generate_sample_vulnerabilities_cve_nvd_data("./sample_vulnerabilities_data.csv",
#                                              [".", "sample_vulnerabilities_cve_nvd_data.json"])

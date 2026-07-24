import pandas
from rapticoressvc.kevc_helper import get_kevc_cisa_data
from rapticoressvc.storage_helpers.files_helper import save_to_json_file

"""
Data-generation helpers for the test fixtures.

The legacy NVD 1.1 yearly-feed generator was removed: NVD data is now fetched on
demand per CVE from the NVD 2.0 API (see rapticoressvc.nvd_data_helper), so tests
mock that fetch rather than pre-generating bulk feed fixtures.
"""


def get_test_cves(test_file_destination):
    excel_data_df = pandas.read_csv(test_file_destination)
    cve_numbers_list = list(excel_data_df.get("cve_number", []))
    cve_numbers = [cve.strip() for cve_numbers in cve_numbers_list for cve in cve_numbers.split('|')]
    cve_numbers = list(dict.fromkeys(cve_numbers)) or []
    return cve_numbers


def generate_kevc_cisa_data(kevc_data_destination):
    kevc_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data, last_modified = get_kevc_cisa_data(kevc_url)
    kevc_data = {'last_modified': last_modified, 'data': data}
    save_to_json_file(kevc_data, kevc_data_destination)

# generate_kevc_cisa_data([".", "kevc_cisa_data.json"])

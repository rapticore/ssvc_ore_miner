import logging
from pathlib import Path

import pandas
from rapticoressvc.kevc_helper import get_kevc_cisa_data
from rapticoressvc.nvd_data_helper import get_nvd_file
from rapticoressvc.storage_helpers.files_helper import read_from_json_file
from rapticoressvc.storage_helpers.files_helper import save_to_json_file

"""
Generate NVD data for CVEs mentioned in sample_vulnerabilities_data.csv
"""


def get_test_cves(test_file_destination):
    excel_data_df = pandas.read_csv(test_file_destination)
    cve_numbers_list = list(excel_data_df.get("cve_number", []))
    cve_numbers = [cve.strip() for cve_numbers in cve_numbers_list for cve in cve_numbers.split('|')]
    cve_numbers = list(dict.fromkeys(cve_numbers)) or []
    return cve_numbers


def generate_sample_vulnerabilities_cve_nvd_data():
    allowed_nvd_data_years = ["2023", "2022", "2021", "2020", "2019", "2018"]
    sample_vulnerabilities_file_path = (Path(__file__).parent / "sample_vulnerabilities_data.csv").resolve()
    cve_nvd_data_current = read_from_json_file(["sample_vulnerabilities_cve_nvd_data.json"],
                                               start_location=Path(__file__).parent)
    cves_current = []
    for data in cve_nvd_data_current["CVE_Items"]:
        cve_id = data["cve"]["CVE_data_meta"]["ID"]
        cve_id not in cves_current and cves_current.append(cve_id)
    cves = get_test_cves(sample_vulnerabilities_file_path)
    cves_new = [cve for cve in cves if cve and cve not in cves_current]
    if cves_new:
        cve_nvd_data_new = []
        nvd_data_years = [year for year in allowed_nvd_data_years
                          if any(str(cve).startswith(f"CVE-{year}") for cve in cves_new)]
        for year in nvd_data_years:
            try:
                zip_url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
                nvd_file, last_modified = get_nvd_file(zip_url, None)
                if not nvd_file:
                    continue
                for data in nvd_file["CVE_Items"]:
                    cve_id = data["cve"]["CVE_data_meta"]["ID"]
                    cve_id in cves_new and cve_nvd_data_new.append(data)
            except Exception as e:
                logging.exception(e)
        cve_nvd_data_new and cve_nvd_data_current["CVE_Items"].extend(cve_nvd_data_new)
        save_to_json_file(cve_nvd_data_current, ["sample_vulnerabilities_cve_nvd_data.json"],
                          start_location=Path(__file__).parent)


"""
Generate kevc_cisa_data.json
"""


def generate_kevc_cisa_data(kevc_data_destination):
    kevc_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data, last_modified = get_kevc_cisa_data(kevc_url)
    kevc_data = {'last_modified': last_modified, 'data': data}
    save_to_json_file(kevc_data, kevc_data_destination)

# generate_kevc_cisa_data([".", "kevc_cisa_data.json"])

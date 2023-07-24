import os
from pathlib import Path
from unittest import mock

from rapticoressvc.storage_helpers.files_helper import read_from_json_file


def mock_environment_variables(**envvars):
    return mock.patch.dict(os.environ, envvars)


def mock_data(keyword, second_keyword, *args, **kargs):
    mocked_data = None
    if second_keyword == "ssvc_ore":
        mocked_data = None, None
    if keyword == "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
        _data = read_from_json_file(["kevc_cisa_data.json"], start_location=Path(__file__).parent)
        mocked_data = _data.get("data", {}), _data.get("last_modified", "")
    if keyword == "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip" and second_keyword == "ssvc_ore":
        _data = read_from_json_file(["sample_vulnerabilities_cve_nvd_data.json"], start_location=Path(__file__).parent)
        mocked_data = _data, "last_modified_date"
    if keyword == "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip" and second_keyword == "nvd_data":
        _data = read_from_json_file(["nvd_sample_data.json"], start_location=Path(__file__).parent)
        mocked_data = _data.get("data", {}), _data.get("last_modified", "")
    if keyword == "get_kevc_local_data":
        mocked_data = read_from_json_file(["kevc_cves_data.json"], start_location=Path(__file__).parent)
    return mocked_data

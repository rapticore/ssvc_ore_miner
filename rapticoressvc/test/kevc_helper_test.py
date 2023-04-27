import os

from moto import mock_s3
from rapticoressvc import kevc_helper
from rapticoressvc.kevc_helper import check_cve_kevc_status
from rapticoressvc.kevc_helper import update_kevc_data
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.test.testing_helper import mock_environment_variables

BUCKET_NAME = "test_bucket_ssvc"
STORAGE_TYPE = "s3"
REGION = "us-west-2"

KEVC_FILE_NAME = "kevc_cves_data"
KEVC_DATA = {
    'title': 'CISA Catalog of Known Exploited Vulnerabilities',
    'catalogVersion': '2023.04.21',
    'dateReleased': '2023-04-21T09:54:52.3190Z',
    'count': 922,
    'vulnerabilities': [
        {
            'cveID': 'CVE-2021-27104',
            'vendorProject': 'Accellion',
            'product': 'FTA',
            'vulnerabilityName': 'Accellion FTA OS Command Injection Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Accellion FTA 9_12_370 and earlier is affected by OS command execution via a crafted POST request to various admin endpoints.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2021-11-17',
            'notes': ''
        },
        {
            'cveID': 'CVE-2021-27102',
            'vendorProject': 'Accellion',
            'product': 'FTA',
            'vulnerabilityName': 'Accellion FTA OS Command Injection Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Accellion FTA 9_12_411 and earlier is affected by OS command execution via a local web service call.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2021-11-17',
            'notes': ''
        },
        {
            'cveID': 'CVE-2021-27101',
            'vendorProject': 'Accellion',
            'product': 'FTA',
            'vulnerabilityName': 'Accellion FTA SQL Injection Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Accellion FTA 9_12_370 and earlier is affected by SQL injection via a crafted Host header in a request to document_root.html.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2021-11-17',
            'notes': ''
        },
        {
            'cveID': 'CVE-2021-27103',
            'vendorProject': 'Accellion',
            'product': 'FTA',
            'vulnerabilityName': 'Accellion FTA SSRF Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Accellion FTA 9_12_411 and earlier is affected by SSRF via a crafted POST request to wmProgressstat.html.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2021-11-17',
            'notes': ''
        },
        {
            'cveID': 'CVE-2021-21017',
            'vendorProject': 'Adobe',
            'product': 'Acrobat and Reader',
            'vulnerabilityName': 'Adobe Acrobat and Reader Heap-based Buffer Overflow Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a heap-based buffer overflow vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2021-11-17',
            'notes': ''
        },
        {
            'cveID': 'CVE-2021-28550',
            'vendorProject': 'Adobe',
            'product': 'Acrobat and Reader',
            'vulnerabilityName': 'Adobe Acrobat and Reader Use-After-Free Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2021-11-17',
            'notes': ''
        },
        {
            'cveID': 'CVE-2018-4939',
            'vendorProject': 'Adobe',
            'product': 'ColdFusion',
            'vulnerabilityName': 'Adobe ColdFusion Deserialization of Untrusted Data vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Adobe ColdFusion Update 5 and earlier versions, ColdFusion 11 Update 13 and earlier versions have an exploitable Deserialization of Untrusted Data vulnerability. Successful exploitation could lead to arbitrary code execution.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2022-05-03',
            'notes': ''
        },
        {
            'cveID': 'CVE-2018-15961',
            'vendorProject': 'Adobe',
            'product': 'ColdFusion',
            'vulnerabilityName': 'Adobe ColdFusion Remote Code Execution',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Adobe ColdFusion versions July 12 release (2018.0.0.310739), Update 6 and earlier, and Update 14 and earlier have an unrestricted file upload vulnerability. Successful exploitation could lead to arbitrary code execution.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2022-05-03',
            'notes': ''
        },
        {
            'cveID': 'CVE-2018-4878',
            'vendorProject': 'Adobe',
            'product': 'Flash Player',
            'vulnerabilityName': 'Adobe Flash Player Use-After-Free Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'A use-after-free vulnerability was discovered in Adobe Flash Player before 28.0.0.161. This vulnerability occurs due to a dangling pointer in the Primetime SDK related to media player handling of listener objects. A successful attack can lead to arbitrary code execution. This was exploited in the wild in January and February 2018.',
            'requiredAction': 'The impacted product is end-of-life and should be disconnected if still in use.',
            'dueDate': '2022-05-03',
            'notes': ''
        },
        {
            'cveID': 'CVE-2020-5735',
            'vendorProject': 'Amcrest',
            'product': 'Cameras and Network Video Recorder (NVR)',
            'vulnerabilityName': 'Amcrest Camera and NVR Buffer Overflow Vulnerability',
            'dateAdded': '2021-11-03',
            'shortDescription': 'Amcrest cameras and NVR are vulnerable to a stack-based buffer overflow over port 37777. An authenticated remote attacker can abuse this issue to crash the device and possibly execute arbitrary code.',
            'requiredAction': 'Apply updates per vendor instructions.',
            'dueDate': '2022-05-03',
            'notes': ''
        }
    ]
}
KEVC_DATA_FILE_LAST_MODIFIED = "last_modified_date_for_kevc_data_file"


def mock_get_kevc_cisa_data(url, last_modified_old=None):
    mocked_data = None
    if url == "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
        mocked_data = KEVC_DATA, KEVC_DATA_FILE_LAST_MODIFIED
    return mocked_data


@mock_environment_variables(BUCKET_NAME=BUCKET_NAME, STORAGE_TYPE=STORAGE_TYPE)
@mock_s3
def test_kevc_data(mocker):
    if os.environ['STORAGE_TYPE'] == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    mocker.patch.object(kevc_helper, 'get_kevc_cisa_data',
                        side_effect=lambda _url, last_modified_old: mock_get_kevc_cisa_data(_url, last_modified_old))
    update_kevc_data()
    cve_kevc_status_map = {
        "CVE-2021-27104": True,
        "CVE-2021-27101": True,
        "CVE-2021-9999": False
    }
    assert all(check_cve_kevc_status(cve) is cve_kevc_status_map.get(cve) for cve in cve_kevc_status_map.keys())

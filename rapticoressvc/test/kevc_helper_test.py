import os

from moto import mock_s3
from rapticoressvc import kevc_helper
from rapticoressvc.kevc_helper import check_cve_kevc_status
from rapticoressvc.kevc_helper import update_kevc_data
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.test.testing_helper import mock_data

BUCKET_NAME = os.environ.get("BUCKET_NAME")
STORAGE_TYPE = os.environ.get("STORAGE_TYPE")
REGION = os.environ.get("REGION")


@mock_s3
def test_kevc_data(mocker):
    if STORAGE_TYPE == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    mocker.patch.object(kevc_helper, 'get_kevc_cisa_data',
                        side_effect=lambda _url, last_modified_old: mock_data(_url, last_modified_old))
    update_kevc_data()
    cve_kevc_status_map = {
        "CVE-2021-27104": True,
        "CVE-2021-27101": True,
        "CVE-2021-9999": False
    }
    assert all(check_cve_kevc_status(cve) is cve_kevc_status_map.get(cve) for cve in cve_kevc_status_map.keys())

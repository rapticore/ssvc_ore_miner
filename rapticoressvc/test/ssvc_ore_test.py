import os

import pandas
from moto import mock_s3
from rapticoressvc import kevc_helper
from rapticoressvc import nvd_data_helper
from rapticoressvc import ssvc_recommendations
from rapticoressvc.kevc_helper import update_kevc_data
from rapticoressvc.nvd_data_helper import update_nvd_data
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.test.testing_helper import mock_data

BUCKET_NAME = os.environ.get("BUCKET_NAME")
STORAGE_TYPE = os.environ.get("STORAGE_TYPE")
REGION = os.environ.get("REGION")


@mock_s3
def test_sample_vulnerabilities(mocker):
    if STORAGE_TYPE == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_data(_url, "ssvc_ore"))
    mocker.patch.object(kevc_helper, 'get_kevc_local_data',
                        side_effect=lambda bucket_name, file_name, storage_type: mock_data(
                            "get_kevc_local_data", bucket_name, file_name, storage_type))

    update_nvd_data()
    update_kevc_data()

    # sample file
    sample_vulnerabilities_data = []
    excel_data_df = pandas.read_csv("rapticoressvc/test/sample_vulnerabilities_data.csv")
    data_rows = list(excel_data_df.iterrows())
    for row in data_rows:
        row_data = row[1]
        sample_vulnerabilities_data.append({
            "asset": row_data.get("asset_id").strip(),
            "vul_details": [cve.strip() for cve in row_data["cve_number"].strip().split('|')]
            if row_data.get("cve_number").strip() != "None" else row_data.get("vul_severity").strip(),
            "public_status": row_data.get("public_status").strip(),
            "environment": row_data.get("environment").strip(),
            "asset_type": row_data.get("assetType").strip(),
            "asset_criticality": row_data.get("assetCriticality").strip(),
            "ssvc_recommendation": row_data.get("ssvc_recommendation").strip(),
        })

    for data in sample_vulnerabilities_data:
        expected = data.pop("ssvc_recommendation", None)
        actual = ssvc_recommendations(**data)
        assert actual.get("ssvc_rec") == expected

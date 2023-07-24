import os
from pathlib import Path

import pandas
from moto import mock_s3
from rapticoressvc import kevc_helper
from rapticoressvc import nvd_data_helper
from rapticoressvc import ssvc_recommendations
from rapticoressvc.kevc_helper import update_kevc_data
from rapticoressvc.nvd_data_helper import update_nvd_data
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.test.test_data_helper import (
    generate_sample_vulnerabilities_cve_nvd_data,
)
from rapticoressvc.test.testing_helper import mock_data


@mock_s3
def test_sample_vulnerabilities(mocker):
    bucket_name, storage_type, region = os.environ.get("BUCKET_NAME"), os.environ.get("STORAGE_TYPE"), \
                                        os.environ.get("REGION")
    if storage_type == "s3":
        get_s3_client().create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})

    generate_sample_vulnerabilities_cve_nvd_data()

    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_data(_url, "ssvc_ore"))
    mocker.patch.object(kevc_helper, 'get_kevc_local_data',
                        side_effect=lambda _bucket_name, file_name, _storage_type: mock_data(
                            "get_kevc_local_data", _bucket_name, file_name, _storage_type))

    update_nvd_data()
    update_kevc_data()

    # sample file
    sample_vulnerabilities_data = []
    sample_vulnerabilities_file_path = (Path(__file__).parent / "sample_vulnerabilities_data.csv").resolve()
    excel_data_df = pandas.read_csv(sample_vulnerabilities_file_path)
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

    results = {}
    record_number = 1
    for data in sample_vulnerabilities_data:
        expected = data.pop("ssvc_recommendation", None)
        actual = ssvc_recommendations(**data)
        results[record_number] = actual.get("ssvc_rec") == expected
        record_number += 1
    failed_records = [record for record, result in results.items() if not result]
    assert not failed_records

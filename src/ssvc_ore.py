import json
import logging
import argparse
import csv
import sys
import src.svcc_helper
from src import helpers
from src.vector_calculator_helpers import vector_calculate_utility, vector_calculate_exposure, \
    vector_calculate_exploitability, vector_calculate_impact

combined_results = []


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def ssvc_recommendations(cve_number, public_status, environment, asset_type, asset_criticality):
    query = {}
    description = None
    get_data = helpers.input_cve_get_nvd_data(cve_number)
    cvss_vector, cvss_score, nvd_data_local = get_data[1], get_data[2], json.loads(get_data[3])

    try:
        description = nvd_data_local["cve"]["description"]["description_data"][0]["value"]
    except Exception as e:
        logging.error(e)

    exploit_status = vector_calculate_exploitability(cve_number, cvss_vector)
    query["Exploitation"] = exploit_status
    query["Exposure"] = vector_calculate_exposure(cvss_score)
    query["Utility"] = vector_calculate_utility(exploit_status, cvss_vector, public_status)
    query["Impact"] = vector_calculate_impact(environment, asset_type, asset_criticality)

    recommendation = src.svcc_helper.calculate_recommendation(query)
    recommendation = list(recommendation.keys())[0]

    results = dict(description=description, cve=cve_number, cvss_score=cvss_score, cvss_vector=cvss_vector,
                   asset_type=asset_type, environment=environment,
                   public_status=public_status, ssvc_rec=recommendation)

    combined_results.append(results)


def main():
    logging.getLogger()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--single', help="Parameter based entry", action='store_true')
    group.add_argument('--datafile', help="csv file upload - use --file option", action='store_true')

    parser.add_argument(
        "-cn",
        "--cve_number",
        help="CVE number for the vulnerability",
        default=None,
        type=str,
    )

    parser.add_argument(
        "-p",
        "--public_status",
        help="Public Status allowed values. Choices: public, public_restricted, private",
        default="None",
        choices=["public", "public_restricted", "private", "None"],
        type=str,
    )

    parser.add_argument(
        "-e",
        "--environment",
        help="Environment for the asset. Choices: production, non_production, None",
        choices=["production", "non_production", "None"],
        type=str,
    )

    parser.add_argument(
        "-a",
        "--assetType",
        help="Asset Type allowed values. Choices: DB, Compute, Storage, None",
        choices=["DB", "Computer", "Storage", "None"],
        type=str,
    )

    parser.add_argument(
        "-s",
        "--criticality",
        help="Criticality Business value of asset. Choices: critical, high, medium, low",
        choices=["critical", "high", "medium", "low"],
        type=str,
        default="high"
    )

    parser.add_argument(
        "--file",
        help="Provide a vulnerability/host via stdin (e.g. through piping) or --file",
        type=argparse.FileType("r", encoding="utf-8-sig"),
        default=sys.stdin,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Increase output verbosity",
        action="store_true",
        default=False,
    )

    log_level = logging.ERROR
    log_format = "%(message)s"

    args = parser.parse_args()

    if args.verbose:
        log_level = logging.INFO
        log_format = "%(message)s"

    logging.basicConfig(level=log_level, stream=sys.stderr, format=log_format)

    engine_check = helpers.initialize()
    if engine_check:
        if args.datafile:
            data_file = args.file
            reader = csv.DictReader(data_file)
            for row in reader:
                cve_number = str(row['cve_number'])
                environment = str(row['environment'])
                public_status = str(row['public_status'])
                asset_type = str(row['assetType'])
                asset_criticality = str(row['assetCriticality'])
                ssvc_recommendations(cve_number, public_status, environment, asset_type, asset_criticality)
        elif args.single:
            cve_number = str(args.cve_number)
            if cve_number:
                environment = str(args.environment)
                public_status = str(args.public_status)
                asset_type = str(args.assetType)
                asset_criticality = str(args.criticality)
                ssvc_recommendations(cve_number, public_status, environment, asset_type, asset_criticality)
    else:
        sys.exit(1)

    helpers.exel_writer(combined_results)


if __name__ == "__main__":
    main()

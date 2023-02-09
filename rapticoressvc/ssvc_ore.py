import json
import logging
import argparse
import csv
import sys
import rapticoressvc.svcc_helper
from rapticoressvc import helpers
from rapticoressvc.vector_calculator_helpers import vector_calculate_utility, vector_calculate_exposure, \
    vector_calculate_exploitability, vector_calculate_impact

combined_results = []


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

def xstr(s):
    if s == "None":
        return None
    else:
        return str(s)

def xstr_asset_criticality(s):
    if s == "None":
        return "high"
    else:
        return str(s)


def ssvc_recommendations(asset,vul_details, public_status, environment, asset_type, asset_criticality):
    query = {}
    description = None
    severity_list = ["critical", "high", "medium", "low"]
    severity_priority = ["critical", "high"]
    cvss_vector = None
    nvd_data_local = None
    score = None
    exploit_status = None
    recommendation = None
    if vul_details in severity_list:
        score = vul_details
        if vul_details in severity_priority:
            exploit_status = "active"
        else:
            exploit_status = "None"
    else:
        try:
            get_data = helpers.input_cve_get_nvd_data(vul_details)
            cvss_vector, score, nvd_data_local = get_data[1], get_data[2], json.loads(get_data[3])
            exploit_status = vector_calculate_exploitability(vul_details, cvss_vector)
        except Exception as e:
            logging.error(e)

            #todo handle this
        try:
            description = nvd_data_local["cve"]["description"]["description_data"][0]["value"]
        except Exception as e:
            logging.error(e)

    query["Exploitation"] = exploit_status
    query["Exposure"] = vector_calculate_exposure(score)
    query["Utility"] = vector_calculate_utility(exploit_status, cvss_vector, public_status, score)
    query["Impact"] = vector_calculate_impact(environment, asset_type, asset_criticality)

    recommendation = rapticoressvc.svcc_helper.calculate_recommendation(query)
    if recommendation:
        recommendation = list(recommendation.keys())[0]
    else:
        recommendation = "review"

    results = dict(asset=asset, description=description, cve=vul_details, vulnerability_score=score, cvss_vector=cvss_vector,
                   asset_type=asset_type, environment=environment,
                   public_status=public_status, asset_criticality=asset_criticality, ssvc_rec=recommendation)

    logging.info(results)
    combined_results.append(results)
    return results


def main():
    logging.getLogger()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--single', help="Parameter based entry", action='store_true')
    group.add_argument('--datafile', help="csv file upload - use --file option", action='store_true')

    parser.add_argument(
        "-id",
        "--asset_id",
        help="Asset Identifier",
        default=None,
        type=str,
    )

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
        "-vs",
        "--vul_severity",
        help="Vulnerability Severity",
        default="None",
        choices=["critical", "high", "medium", "low"],
        type=str,
    )

    parser.add_argument(
        "-e",
        "--environment",
        help="Environment for the asset. Choices: production, non_production, None",
        choices=["production", "non_production", "None"],
        default="None",
        type=str,
    )

    parser.add_argument(
        "-a",
        "--assetType",
        help="Asset Type allowed values. Choices: DB, Compute, Storage, None",
        choices=["DB", "Compute", "Storage", "None"],
        default="None",
        type=str,
    )

    parser.add_argument(
        "-s",
        "--criticality",
        help="Business Criticality of an asset. Choices: critical, high, medium, low",
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

    log_level = logging.INFO
    log_format = "%(message)s"

    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG

    logging.basicConfig(level=log_level, stream=sys.stderr, format=log_format)
    logging.debug('Initializing......')
    engine_check = helpers.initialize()
    if not engine_check:
        logging.error('DB engine could not be Initialized')
        sys.exit(1)

    logging.debug('DB engine Initialized')
    if args.datafile:
        logging.debug('Processing datafile')
        data_file = args.file
        reader = csv.DictReader(data_file)
        for row in reader:
            asset_id = str(row['asset_id']).rstrip()
            cve_number = str(row['cve_number']).rstrip()
            cve_number = xstr(cve_number)
            vul_severity = str(row['vul_severity']).rstrip()
            environment = str(row['environment']).rstrip()
            public_status = str(row['public_status']).rstrip()
            asset_type = str(row['assetType']).rstrip()
            asset_criticality = str(row['assetCriticality']).rstrip()
            asset_criticality = xstr_asset_criticality(asset_criticality)

            if cve_number:
                ssvc_recommendations(asset_id, cve_number, public_status, environment, asset_type, asset_criticality)
            elif vul_severity:
                ssvc_recommendations(asset_id,vul_severity, public_status, environment, asset_type, asset_criticality)
    elif args.single:
        logging.debug('Processing single parameter based entry')
        cve_number = str(args.cve_number)
        cve_number = xstr(cve_number)
        vul_severity = str(args.vul_severity)
        if cve_number:
            asset_id = str(args.asset_id)
            environment = str(args.environment)
            public_status = str(args.public_status)
            asset_type = str(args.assetType)
            asset_criticality = str(args.criticality)

            ssvc_recommendations(asset_id, cve_number, public_status, environment, asset_type, asset_criticality)
        elif vul_severity:
            asset_id = str(args.asset_id).rstrip()
            environment = str(args.environment)
            public_status = str(args.public_status)
            asset_type = str(args.assetType)
            asset_criticality = str(args.criticality)
            ssvc_recommendations(asset_id, vul_severity, public_status, environment, asset_type, asset_criticality)

    logging.info('Writing results to excel file')
    helpers.excel_writer(combined_results)
    logging.info('Results written to excel file ssvc_recommendations.xlsx')


if __name__ == "__main__":
    main()

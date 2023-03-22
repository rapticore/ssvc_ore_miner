import argparse
import csv
import json
import logging
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


def ssvc_recommendations(asset, vul_details, public_status, environment, asset_type, asset_criticality):
    logging.debug('Initializing......')
    engine_check = helpers.initialize()
    if not engine_check:
        logging.error('DB engine could not be Initialized')
        sys.exit(1)
    logging.debug('DB engine Initialized')
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
            exploit_status = "PoC"
        else:
            exploit_status = "None"
    else:
        if type(vul_details) is not list:
            vul_details = [vul_details]
        exploit_data = []
        for vul_detail in vul_details:
            try:
                get_data = helpers.input_cve_get_nvd_data(vul_detail)
                if get_data:
                    cvss_vector, score, nvd_data_local = get_data[1], get_data[2], json.loads(get_data[3])
                    if cvss_vector:
                        exploit_status = vector_calculate_exploitability(vul_detail, cvss_vector)
                    description = nvd_data_local["cve"]["description"]["description_data"][0]["value"]
                    exploit_data.append(dict(cvss_vector=cvss_vector, score=score, exploit_status=exploit_status,
                                             description=description))
            except Exception as e:
                logging.exception(e)
                # todo handle this
        if len(exploit_data) > 0:
            max_exploit = max(exploit_data, key=lambda x: x['score'])

            exploit_status = max_exploit.get('exploit_status')
            score = max_exploit.get('score')
            cvss_vector = max_exploit.get('cvss_vector')
            description = max_exploit.get('description')

    query["Exploitation"] = exploit_status
    query["Exposure"] = vector_calculate_exposure(score)
    query["Utility"] = vector_calculate_utility(exploit_status, cvss_vector, public_status, score)
    query["Impact"] = vector_calculate_impact(environment, asset_type, asset_criticality)
    recommendation = rapticoressvc.svcc_helper.calculate_recommendation(query)
    if recommendation:
        recommendation = list(recommendation.keys())[0]
    else:
        recommendation = "review"

    results = dict(asset=asset, description=description, cve=vul_details, vulnerability_score=score,
                   cvss_vector=cvss_vector,
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
        help="CVE numbers for the vulnerability separated by '|'",
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
        choices=["db", "compute", "storage", "None", "network"],
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

    if args.datafile:
        logging.debug('Processing datafile')
        data_file = args.file
        reader = csv.DictReader(data_file)
        for row in reader:
            asset_id = str(row['asset_id']).strip()
            cve_number = str(row['cve_number']).strip()
            cve_number = xstr(cve_number)
            cve_list = None
            if cve_number:
                cve_list = cve_number.split('|')
                cve_list = [cve.strip() for cve in cve_list]

            vul_severity = str(row['vul_severity']).strip()
            environment = str(row['environment']).strip()
            public_status = str(row['public_status']).strip()
            asset_type = str(row['assetType']).strip()
            asset_criticality = str(row['assetCriticality']).strip()
            asset_criticality = xstr_asset_criticality(asset_criticality)

            if cve_list:
                ssvc_recommendations(asset_id, cve_list, public_status, environment, asset_type, asset_criticality)
            elif vul_severity:
                ssvc_recommendations(asset_id, vul_severity, public_status, environment, asset_type, asset_criticality)
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
    else:
        parser.print_help()
        exit(1)

    logging.info('Writing results to excel file')
    helpers.excel_writer(combined_results)
    logging.info('Results written to excel file ssvc_recommendations.xlsx')

if __name__ == "__main__":
    main()

import logging

import pandas as pd


def process_cvss_score(value):
    c_score = value.split("/")
    result = {}
    for val in c_score:
        key = val.split(":")[0]
        s_value = val.split(":")[1]
        result[key] = s_value
    return result


def nvd_parser(cvss_vector):
    score_dict = process_cvss_score(cvss_vector)
    if score_dict.get("E"):
        if score_dict.get("E") == "U":
            return "None"
        if score_dict.get("E") == "P":
            return "PoC"
        if score_dict.get("E") == "F" or score_dict.get("E") == "H":
            return "active"
    else:
        return "None"


def excel_writer(data):
    try:
        # Create a Pandas Excel writer using XlsxWriter as the engine.
        writer = pd.ExcelWriter('ssvc_recommendations.xlsx', engine='xlsxwriter')  \
            # pylint: disable=abstract-class-instantiated
        df1 = pd.DataFrame(data)
        # Write each dataframe to a different worksheet.
        df1.to_excel(writer, sheet_name='ec2')

        # Close the Pandas Excel writer and output the Excel file.
        writer.close()
    except Exception as e:
        logging.exception(e)

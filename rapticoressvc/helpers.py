import datetime
import json
import logging
import os
import sqlite3
from pathlib import Path
from urllib.request import pathname2url
import requests
import pandas as pd


def execute_threat_intel_tbl_count():
    db_connection, conn = get_db_conn()[0], get_db_conn()[1]
    data = db_connection.execute(
        "SELECT COUNT(1) FROM threatIntel")
    data = data.fetchall()
    if data:
        return data[0]
    else:
        return None


def get_db_conn():
    try:
        connection = sqlite3.connect('/tmp/threatdb.db')
        cursor = connection.cursor()
        if connection and cursor:
            return cursor, connection
        else:
            return None
    except Exception as e:
        logging.exception(e)
    return None


def initialize_db():
    try:
        connection = sqlite3.connect('/tmp/threatdb.db')
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS threatIntel (id varchar (25) NOT NULL PRIMARY KEY, data json)")
        return True
    except Exception as e:
        logging.exception(e)
    return None


def get_cisa_kevc():
    # todo load url from config.yml
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url, stream=True)
    db_connection = None
    conn = None
    threat_data = json.loads(response.content)
    db_foo = get_db_conn()
    if db_foo:
        db_connection, conn = db_foo[0], db_foo[1]
    for data in threat_data["vulnerabilities"]:
        db_connection.execute("insert into threatIntel values (?, ?)", [data['cveID'], json.dumps(data)])
        conn.commit()
    conn.close()


def validate_db_time():
    try:
        if os.path.exists('/tmp/threatdb.db'):
            c_time = os.path.getctime('/tmp/threatdb.db')
            dt_c = datetime.datetime.fromtimestamp(c_time)
            today = datetime.datetime.now()
            delta = today - dt_c
            days_from_creation = delta.days
            return days_from_creation > 0
    except Exception as e:
        logging.exception(e)
    return False


def initialize():
    try:
        dburi = 'file:{}?mode=rw'.format(pathname2url('/tmp/threatdb.db'))
        db_validation = validate_db_time()
        path = Path('/tmp/threatdb.db')
        if path and db_validation:
            os.remove("/tmp/threatdb.db")
            logging.info('threatdb cleaned up')
        check = sqlite3.connect(dburi, uri=True)
        if check:
            return True
    except sqlite3.OperationalError:
        try:
            db_connection = initialize_db()
            if db_connection:
                get_cisa_kevc()
                # todo add check whether the db was loaded.
                return True
        except Exception as e:
            logging.exception(e)


def execute_db(query_data):
    db_connection, conn = get_db_conn()[0], get_db_conn()[1]
    data = db_connection.execute(
        "SELECT * FROM threatIntel WHERE id=?", [query_data]
    )
    data = data.fetchall()
    if data:
        return data
    else:
        return None


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


def select_all_tasks(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM threatIntel")
    rows = cur.fetchall()
    return rows


def excel_writer(data):
    try:
        # Create a Pandas Excel writer using XlsxWriter as the engine.
        writer = pd.ExcelWriter('ssvc_recommendations.xlsx', engine='xlsxwriter')
        df1 = pd.DataFrame(data)
        # Write each dataframe to a different worksheet.
        df1.to_excel(writer, sheet_name='ec2')

        # Close the Pandas Excel writer and output the Excel file.
        writer.close()
    except Exception as e:
        logging.exception(e)

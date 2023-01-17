import json
import sqlite3
import requests
import io
import zipfile
from nested_lookup import nested_lookup
import pandas as pd


def execute_nvd_tbl_count():
    db_connection, conn = get_db_conn()[0], get_db_conn()[1]
    data = db_connection.execute(
        "SELECT COUNT(1) FROM nvd")
    data = data.fetchone()
    if data:
        return data[0]
    else:
        return None

def execute_threatIntel_tbl_count():
    db_connection, conn = get_db_conn()[0], get_db_conn()[1]
    data = db_connection.execute(
        "SELECT COUNT(1) FROM threatIntel")
    data = data.fetchall()
    if data:
        return data[0]
    else:
        return None

def execute_nvd_tbl_query(query_data):
    db_connection, conn = get_db_conn()[0], get_db_conn()[1]
    data = db_connection.execute(
        "SELECT * FROM nvd WHERE id=?", [query_data]
    )
    data = data.fetchall()
    if data:
        return data[0]
    else:
        return None


def get_db_conn():
    try:
        conn = sqlite3.connect('threatdb.db')
        foo_connection = conn.cursor()
        if conn and foo_connection:
            return foo_connection, conn
        else:
            return None
    except Exception as e:
        print(e)
    return None


def download_extract_zip(url):
    response = requests.get(url)
    with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:
        for zipinfo in thezip.infolist():
            with thezip.open(zipinfo) as thefile:
                file = json.loads(thefile.read())
                return file


def initialize_nvdb_tlb():
    try:
        conn = sqlite3.connect('threatdb.db')
        foo_connection = conn.cursor()
        foo_connection.execute(
            "CREATE TABLE IF NOT EXISTS nvd (id varchar (25),cve_vector varchar(50), cve_score varchar(50),data json)")
        return True
    except Exception as e:
        print(e)
    return None


def load_nvd_tlb(nvddata):
    print("I am here in load_nvd_tlb")
    db_connection = None
    conn = None
    db_foo = get_db_conn()
    if db_foo:
        db_connection, conn = db_foo[0], db_foo[1]
    for data in nvddata["CVE_Items"]:
        cve_id = data["cve"]['CVE_data_meta']['ID']
        impact = data['impact']
        if nested_lookup('vectorString', impact):
            cve_vector = nested_lookup('vectorString', impact)[0]
        else:
            cve_vector = None
        if nested_lookup('baseScore', impact):
            cve_score = nested_lookup('baseScore', impact)[0]
        else:
            cve_score = None
        db_connection.execute("insert into nvd values (?, ?, ?, ?)", [cve_id, cve_vector, cve_score, json.dumps(data)])
    conn.commit()
    conn.close()


def get_nvd_data():
    """
    check first if the data is already present.

    """
    check = execute_nvd_tbl_count()
    if check:
        return True
    else:
        years = ["2022", "2021", "2020", "2019", "2018"]
        for year in years:
            zipurl = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
            print(zipurl)
            nvddata = download_extract_zip(zipurl)
            load_nvd_tlb(nvddata)


def initialize_nvdb():

    check = initialize_nvdb_tlb()
    if check:
        get_nvd_data()
        return True


def initialize_db():
    try:
        conn = sqlite3.connect('threatdb.db')
        # table_name = "threatIntel"
        foo_connection = conn.cursor()
        foo_connection.execute("CREATE TABLE IF NOT EXISTS threatIntel (id varchar (25), data json)")
        return True
    except Exception as e:
        print(e)
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


def initialize():
    try:
        db_connection = initialize_db()
        if db_connection:
            get_cisa_kevc()
            check = initialize_nvdb()
            # todo add check whether the db was loaded.
            return check
    except Exception as e:
        print(e)


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
    foo_dic = {}
    for val in c_score:
        key = val.split(":")[0]
        s_value = val.split(":")[1]
        foo_dic[key] = s_value
    return foo_dic


def nvd_praser(cvss_vector):
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


def input_cve_get_nvd_data(cve_number):
    nvd_data = execute_nvd_tbl_query(cve_number)
    return nvd_data

def exel_writer(data):
    try:
        # Create a Pandas Excel writer using XlsxWriter as the engine.
        writer = pd.ExcelWriter('ssvc_recommendations.xlsx', engine='xlsxwriter')
        df1 = pd.DataFrame(data)
        # Write each dataframe to a different worksheet.
        df1.to_excel(writer, sheet_name='ec2')

        # Close the Pandas Excel writer and output the Excel file.
        writer.close()
    except Exception as e:
        print(e)
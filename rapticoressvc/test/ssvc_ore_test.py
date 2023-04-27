import os

import pandas
from moto import mock_s3
from rapticoressvc import kevc_helper
from rapticoressvc import nvd_data_helper
from rapticoressvc import ssvc_recommendations
from rapticoressvc.kevc_helper import update_kevc_data
from rapticoressvc.nvd_data_helper import update_nvd_data
from rapticoressvc.storage_helpers.files_helper import read_from_json_file
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.test.testing_helper import mock_environment_variables

BUCKET_NAME = "test_bucket_ssvc"
STORAGE_TYPE = "s3"
REGION = "us-west-2"

NVD_DATA = {
    "CVE_data_type": "CVE",
    "CVE_data_format": "MITRE",
    "CVE_data_version": "4.0",
    "CVE_data_numberOfCVEs": "3796",
    "CVE_data_timestamp": "2023-03-31T07:00Z",
    "CVE_Items": []  # populated with test_cves_nvd_data.json
}
NVD_DATA_2023_FILE_LAST_MODIFIED = "last_modified_date_for_2023_data_file"

KEVC_STORED_DATA = {"last_modified": "Mon, 17 Apr 2023 14:02:01 GMT",
                    "active_exploit_cves": [
                        "CVE-2021-27104",
                        "CVE-2021-27102", "CVE-2021-27101", "CVE-2021-27103",
                        "CVE-2021-21017", "CVE-2021-28550", "CVE-2018-4939", "CVE-2018-15961",
                        "CVE-2018-4878", "CVE-2020-5735", "CVE-2019-2215", "CVE-2020-0041",
                        "CVE-2020-0069", "CVE-2017-9805", "CVE-2021-42013", "CVE-2021-41773",
                        "CVE-2019-0211", "CVE-2016-4437", "CVE-2019-17558", "CVE-2020-17530",
                        "CVE-2017-5638", "CVE-2018-11776", "CVE-2021-30858", "CVE-2019-6223",
                        "CVE-2021-30860", "CVE-2020-27930", "CVE-2021-30807", "CVE-2020-27950",
                        "CVE-2020-27932", "CVE-2020-9818", "CVE-2020-9819", "CVE-2021-30762",
                        "CVE-2021-1782", "CVE-2021-1870", "CVE-2021-1871", "CVE-2021-1879",
                        "CVE-2021-30661", "CVE-2021-30666", "CVE-2021-30713", "CVE-2021-30657",
                        "CVE-2021-30665", "CVE-2021-30663", "CVE-2021-30761", "CVE-2021-30869",
                        "CVE-2020-9859", "CVE-2021-20090", "CVE-2021-27562", "CVE-2021-28664",
                        "CVE-2021-28663", "CVE-2019-3398", "CVE-2021-26084", "CVE-2019-11580",
                        "CVE-2019-3396", "CVE-2021-42258", "CVE-2020-3452", "CVE-2020-3580",
                        "CVE-2021-1497", "CVE-2021-1498", "CVE-2018-0171", "CVE-2020-3118",
                        "CVE-2020-3566", "CVE-2020-3569", "CVE-2020-3161", "CVE-2019-1653",
                        "CVE-2018-0296", "CVE-2019-13608", "CVE-2020-8193", "CVE-2020-8195",
                        "CVE-2020-8196", "CVE-2019-19781", "CVE-2019-11634", "CVE-2020-29557",
                        "CVE-2020-25506", "CVE-2018-15811", "CVE-2018-18325", "CVE-2017-9822",
                        "CVE-2019-15752", "CVE-2020-8515", "CVE-2018-7600", "CVE-2021-22205",
                        "CVE-2018-6789", "CVE-2020-8657", "CVE-2020-8655", "CVE-2020-5902",
                        "CVE-2021-22986", "CVE-2021-35464", "CVE-2019-5591", "CVE-2020-12812",
                        "CVE-2018-13379", "CVE-2020-16010", "CVE-2020-15999", "CVE-2021-21166",
                        "CVE-2020-16017", "CVE-2021-37976", "CVE-2020-16009", "CVE-2021-30632",
                        "CVE-2020-16013", "CVE-2021-30633", "CVE-2021-21148", "CVE-2021-37973",
                        "CVE-2021-30551", "CVE-2021-37975", "CVE-2020-6418", "CVE-2021-30554",
                        "CVE-2021-21206", "CVE-2021-38000", "CVE-2021-38003", "CVE-2021-21224",
                        "CVE-2021-21193", "CVE-2021-21220", "CVE-2021-30563", "CVE-2020-4430",
                        "CVE-2020-4427", "CVE-2020-4428", "CVE-2019-4716", "CVE-2016-3715",
                        "CVE-2016-3718", "CVE-2020-15505", "CVE-2021-30116", "CVE-2020-7961",
                        "CVE-2021-23874", "CVE-2021-22506", "CVE-2021-22502", "CVE-2014-1812",
                        "CVE-2021-38647", "CVE-2016-0167", "CVE-2020-0878", "CVE-2021-31955",
                        "CVE-2021-1647", "CVE-2021-33739", "CVE-2016-0185", "CVE-2020-0683",
                        "CVE-2020-17087", "CVE-2021-33742", "CVE-2021-31199", "CVE-2021-33771",
                        "CVE-2021-31956", "CVE-2021-31201", "CVE-2021-31979", "CVE-2020-0938",
                        "CVE-2020-17144", "CVE-2020-0986", "CVE-2020-1020", "CVE-2021-38645",
                        "CVE-2021-34523", "CVE-2017-7269", "CVE-2021-36948", "CVE-2021-38649",
                        "CVE-2020-0688", "CVE-2017-0143", "CVE-2016-7255", "CVE-2019-0708",
                        "CVE-2021-34473", "CVE-2020-1464", "CVE-2021-1732", "CVE-2021-34527",
                        "CVE-2021-31207", "CVE-2019-0803", "CVE-2020-1040", "CVE-2021-28310",
                        "CVE-2020-1350", "CVE-2021-26411", "CVE-2019-0859", "CVE-2021-40444",
                        "CVE-2017-8759", "CVE-2018-8653", "CVE-2019-0797", "CVE-2021-36942",
                        "CVE-2019-1215", "CVE-2018-0798", "CVE-2018-0802", "CVE-2012-0158",
                        "CVE-2015-1641", "CVE-2021-27085", "CVE-2019-0541", "CVE-2017-11882",
                        "CVE-2020-0674", "CVE-2021-27059", "CVE-2019-1367", "CVE-2017-0199",
                        "CVE-2020-1380", "CVE-2019-1429", "CVE-2017-11774", "CVE-2020-0968",
                        "CVE-2020-1472", "CVE-2021-26855", "CVE-2021-26858", "CVE-2021-27065",
                        "CVE-2020-1054", "CVE-2021-1675", "CVE-2021-34448", "CVE-2020-0601",
                        "CVE-2019-0604", "CVE-2020-0646", "CVE-2019-0808", "CVE-2021-26857",
                        "CVE-2020-1147", "CVE-2019-1214", "CVE-2016-3235", "CVE-2019-0863",
                        "CVE-2021-36955", "CVE-2021-38648", "CVE-2020-6819", "CVE-2020-6820",
                        "CVE-2019-17026", "CVE-2019-15949", "CVE-2020-26919", "CVE-2019-19356",
                        "CVE-2020-2555", "CVE-2012-3152", "CVE-2020-14871", "CVE-2015-4852",
                        "CVE-2020-14750", "CVE-2020-14882", "CVE-2020-14883", "CVE-2020-8644",
                        "CVE-2019-18935", "CVE-2021-22893", "CVE-2020-8243", "CVE-2021-22900",
                        "CVE-2021-22894", "CVE-2020-8260", "CVE-2021-22899", "CVE-2019-11510",
                        "CVE-2019-11539", "CVE-2021-1906", "CVE-2021-1905", "CVE-2020-10221",
                        "CVE-2021-35395", "CVE-2017-16651", "CVE-2020-11652", "CVE-2020-11651",
                        "CVE-2020-16846", "CVE-2018-2380", "CVE-2010-5326", "CVE-2016-9563",
                        "CVE-2020-6287", "CVE-2020-6207", "CVE-2016-3976", "CVE-2019-16256",
                        "CVE-2020-10148", "CVE-2021-35211", "CVE-2016-3643", "CVE-2020-10199",
                        "CVE-2021-20021", "CVE-2019-7481", "CVE-2021-20022", "CVE-2021-20023",
                        "CVE-2021-20016", "CVE-2020-12271", "CVE-2020-10181", "CVE-2017-6327",
                        "CVE-2019-18988", "CVE-2017-9248", "CVE-2021-31755", "CVE-2020-10987",
                        "CVE-2018-14558", "CVE-2018-20062", "CVE-2019-9082", "CVE-2019-18187",
                        "CVE-2020-8467", "CVE-2020-8468", "CVE-2020-24557", "CVE-2020-8599",
                        "CVE-2021-36742", "CVE-2021-36741", "CVE-2019-20085", "CVE-2020-5849",
                        "CVE-2020-5847", "CVE-2019-16759", "CVE-2020-17496", "CVE-2019-5544",
                        "CVE-2020-3992", "CVE-2020-3950", "CVE-2021-22005", "CVE-2020-3952",
                        "CVE-2021-21972", "CVE-2021-21985", "CVE-2020-4006", "CVE-2020-25213",
                        "CVE-2020-11738", "CVE-2019-9978", "CVE-2021-27561", "CVE-2021-40539",
                        "CVE-2020-10189", "CVE-2019-8394", "CVE-2020-29583", "CVE-2021-22204",
                        "CVE-2021-40449", "CVE-2021-42321", "CVE-2021-42292", "CVE-2020-11261",
                        "CVE-2018-14847", "CVE-2021-37415", "CVE-2021-40438", "CVE-2021-44077",
                        "CVE-2021-44515", "CVE-2019-13272", "CVE-2021-35394", "CVE-2019-7238",
                        "CVE-2019-0193", "CVE-2021-44168", "CVE-2017-17562", "CVE-2017-12149",
                        "CVE-2010-1871", "CVE-2020-17463", "CVE-2020-8816", "CVE-2019-10758",
                        "CVE-2021-44228", "CVE-2021-43890", "CVE-2021-4102", "CVE-2021-22017",
                        "CVE-2021-36260", "CVE-2020-6572", "CVE-2019-1458", "CVE-2013-3900",
                        "CVE-2019-2725", "CVE-2019-9670", "CVE-2018-13382", "CVE-2018-13383",
                        "CVE-2019-1579", "CVE-2019-10149", "CVE-2015-7450", "CVE-2017-1000486",
                        "CVE-2019-7609", "CVE-2021-27860", "CVE-2021-32648", "CVE-2021-25296",
                        "CVE-2021-25297", "CVE-2021-25298", "CVE-2021-40870", "CVE-2021-33766",
                        "CVE-2021-21975", "CVE-2021-21315", "CVE-2021-22991", "CVE-2020-14864",
                        "CVE-2020-13671", "CVE-2020-11978", "CVE-2020-13927", "CVE-2006-1547",
                        "CVE-2012-0391", "CVE-2018-8453", "CVE-2021-35247", "CVE-2022-22587",
                        "CVE-2021-20038", "CVE-2020-5722", "CVE-2020-0787", "CVE-2017-5689",
                        "CVE-2014-1776", "CVE-2014-6271", "CVE-2014-7169", "CVE-2022-21882",
                        "CVE-2021-36934", "CVE-2020-0796", "CVE-2018-1000861", "CVE-2017-9791",
                        "CVE-2017-8464", "CVE-2017-10271", "CVE-2017-0263", "CVE-2017-0262",
                        "CVE-2017-0145", "CVE-2017-0144", "CVE-2016-3088", "CVE-2015-2051",
                        "CVE-2015-1635", "CVE-2015-1130", "CVE-2014-4404", "CVE-2022-22620",
                        "CVE-2022-24086", "CVE-2022-0609", "CVE-2019-0752", "CVE-2018-8174",
                        "CVE-2018-20250", "CVE-2018-15982", "CVE-2017-9841", "CVE-2014-1761",
                        "CVE-2013-3906", "CVE-2022-23131", "CVE-2022-23134", "CVE-2022-24682",
                        "CVE-2017-8570", "CVE-2017-0222", "CVE-2014-6352", "CVE-2022-20708",
                        "CVE-2022-20703", "CVE-2022-20701", "CVE-2022-20700", "CVE-2022-20699",
                        "CVE-2021-41379", "CVE-2020-1938", "CVE-2020-11899", "CVE-2019-16928",
                        "CVE-2019-1652", "CVE-2019-1297", "CVE-2018-8581", "CVE-2018-8298",
                        "CVE-2018-0180", "CVE-2018-0179", "CVE-2018-0175", "CVE-2018-0174",
                        "CVE-2018-0173", "CVE-2018-0172", "CVE-2018-0167", "CVE-2018-0161",
                        "CVE-2018-0159", "CVE-2018-0158", "CVE-2018-0156", "CVE-2018-0155",
                        "CVE-2018-0154", "CVE-2018-0151", "CVE-2017-8540", "CVE-2017-6744",
                        "CVE-2017-6743", "CVE-2017-6740", "CVE-2017-6739", "CVE-2017-6738",
                        "CVE-2017-6737", "CVE-2017-6736", "CVE-2017-6663", "CVE-2017-6627",
                        "CVE-2017-12319", "CVE-2017-12240", "CVE-2017-12238", "CVE-2017-12237",
                        "CVE-2017-12235", "CVE-2017-12234", "CVE-2017-12233", "CVE-2017-12232",
                        "CVE-2017-12231", "CVE-2017-11826", "CVE-2017-11292", "CVE-2017-0261",
                        "CVE-2017-0001", "CVE-2016-8562", "CVE-2016-7855", "CVE-2016-7262",
                        "CVE-2016-7193", "CVE-2016-5195", "CVE-2016-4117", "CVE-2016-1019",
                        "CVE-2016-0099", "CVE-2015-7645", "CVE-2015-5119", "CVE-2015-4902",
                        "CVE-2015-3043", "CVE-2015-2590", "CVE-2015-2545", "CVE-2015-2424",
                        "CVE-2015-2387", "CVE-2015-1701", "CVE-2015-1642", "CVE-2014-4114",
                        "CVE-2014-0496", "CVE-2013-5065", "CVE-2013-3897", "CVE-2013-3346",
                        "CVE-2013-1675", "CVE-2013-1347", "CVE-2013-0641", "CVE-2013-0640",
                        "CVE-2013-0632", "CVE-2012-4681", "CVE-2012-1856", "CVE-2012-1723",
                        "CVE-2012-1535", "CVE-2012-0507", "CVE-2011-3544", "CVE-2011-1889",
                        "CVE-2011-0611", "CVE-2010-3333", "CVE-2010-0232", "CVE-2010-0188",
                        "CVE-2009-3129", "CVE-2009-1123", "CVE-2008-3431", "CVE-2008-2992",
                        "CVE-2004-0210", "CVE-2002-0367", "CVE-2022-26486", "CVE-2022-26485",
                        "CVE-2021-21973", "CVE-2020-8218", "CVE-2019-11581", "CVE-2017-6077",
                        "CVE-2016-6277", "CVE-2013-0631", "CVE-2013-0629", "CVE-2013-0625",
                        "CVE-2009-3960", "CVE-2020-5135", "CVE-2019-1405", "CVE-2019-1322",
                        "CVE-2019-1315", "CVE-2019-1253", "CVE-2019-1132", "CVE-2019-1129",
                        "CVE-2019-1069", "CVE-2019-1064", "CVE-2019-0841", "CVE-2019-0543",
                        "CVE-2018-8120", "CVE-2017-0101", "CVE-2016-3309", "CVE-2015-2546",
                        "CVE-2022-26318", "CVE-2022-26143", "CVE-2022-21999", "CVE-2021-42237",
                        "CVE-2021-22941", "CVE-2020-9377", "CVE-2020-9054", "CVE-2020-7247",
                        "CVE-2020-5410", "CVE-2020-25223", "CVE-2020-2506", "CVE-2020-2021",
                        "CVE-2020-1956", "CVE-2020-1631", "CVE-2019-6340", "CVE-2019-2616",
                        "CVE-2019-16920", "CVE-2019-15107", "CVE-2019-12991", "CVE-2019-12989",
                        "CVE-2019-11043", "CVE-2019-10068", "CVE-2019-1003030", "CVE-2019-0903",
                        "CVE-2018-8414", "CVE-2018-8373", "CVE-2018-6961", "CVE-2018-14839",
                        "CVE-2018-1273", "CVE-2018-11138", "CVE-2018-0147", "CVE-2018-0125",
                        "CVE-2017-6334", "CVE-2017-6316", "CVE-2017-3881", "CVE-2017-12617",
                        "CVE-2017-12615", "CVE-2017-0146", "CVE-2016-7892", "CVE-2016-4171",
                        "CVE-2016-1555", "CVE-2016-11021", "CVE-2016-10174", "CVE-2016-0752",
                        "CVE-2015-4068", "CVE-2015-3035", "CVE-2015-1427", "CVE-2015-1187",
                        "CVE-2015-0666", "CVE-2014-6332", "CVE-2014-6324", "CVE-2014-6287",
                        "CVE-2014-3120", "CVE-2014-0130", "CVE-2013-5223", "CVE-2013-4810",
                        "CVE-2013-2251", "CVE-2012-1823", "CVE-2010-4345", "CVE-2010-4344",
                        "CVE-2010-3035", "CVE-2010-2861", "CVE-2009-2055", "CVE-2009-1151",
                        "CVE-2009-0927", "CVE-2005-2773", "CVE-2022-1096", "CVE-2022-0543",
                        "CVE-2021-38646", "CVE-2021-34486", "CVE-2021-26085", "CVE-2021-20028",
                        "CVE-2019-7483", "CVE-2018-8440", "CVE-2018-8406", "CVE-2018-8405",
                        "CVE-2017-0213", "CVE-2017-0059", "CVE-2017-0037", "CVE-2016-7201",
                        "CVE-2016-7200", "CVE-2016-0189", "CVE-2016-0151", "CVE-2016-0040",
                        "CVE-2015-2426", "CVE-2015-2419", "CVE-2015-1770", "CVE-2013-3660",
                        "CVE-2013-2729", "CVE-2013-2551", "CVE-2013-2465", "CVE-2013-1690",
                        "CVE-2012-5076", "CVE-2012-2539", "CVE-2012-2034", "CVE-2012-0518",
                        "CVE-2011-2005", "CVE-2010-4398", "CVE-2022-26871", "CVE-2022-1040",
                        "CVE-2021-34484", "CVE-2021-28799", "CVE-2021-21551", "CVE-2018-10562",
                        "CVE-2018-10561", "CVE-2022-22965", "CVE-2022-22675", "CVE-2022-22674",
                        "CVE-2021-45382", "CVE-2021-3156", "CVE-2021-31166", "CVE-2017-0148",
                        "CVE-2022-23176", "CVE-2021-42287", "CVE-2021-42278", "CVE-2021-39793",
                        "CVE-2021-27852", "CVE-2021-22600", "CVE-2020-2509", "CVE-2017-11317",
                        "CVE-2022-24521", "CVE-2018-7602", "CVE-2018-20753", "CVE-2015-5123",
                        "CVE-2015-5122", "CVE-2015-3113", "CVE-2015-2502", "CVE-2015-0313",
                        "CVE-2015-0311", "CVE-2014-9163", "CVE-2022-22954", "CVE-2022-22960",
                        "CVE-2022-1364", "CVE-2019-3929", "CVE-2019-16057", "CVE-2018-7841",
                        "CVE-2016-4523", "CVE-2014-0780", "CVE-2010-5330", "CVE-2007-3010",
                        "CVE-2018-6882", "CVE-2019-3568", "CVE-2022-22718", "CVE-2022-29464",
                        "CVE-2022-26904", "CVE-2022-21919", "CVE-2022-0847", "CVE-2021-41357",
                        "CVE-2021-40450", "CVE-2019-1003029", "CVE-2021-1789", "CVE-2019-8506",
                        "CVE-2014-4113", "CVE-2014-0322", "CVE-2014-0160", "CVE-2022-1388",
                        "CVE-2022-30525", "CVE-2022-22947", "CVE-2022-20821", "CVE-2021-1048",
                        "CVE-2021-0920", "CVE-2021-30883", "CVE-2020-1027", "CVE-2020-0638",
                        "CVE-2019-7286", "CVE-2019-7287", "CVE-2019-0676", "CVE-2019-5786",
                        "CVE-2019-0703", "CVE-2019-0880", "CVE-2019-13720", "CVE-2019-11707",
                        "CVE-2019-11708", "CVE-2019-8720", "CVE-2019-18426", "CVE-2019-1385",
                        "CVE-2019-1130", "CVE-2018-5002", "CVE-2018-8589", "CVE-2018-8611",
                        "CVE-2018-19953", "CVE-2018-19949", "CVE-2018-19943", "CVE-2017-0147",
                        "CVE-2017-0022", "CVE-2017-0005", "CVE-2017-0149", "CVE-2017-0210",
                        "CVE-2017-8291", "CVE-2017-8543", "CVE-2017-18362", "CVE-2016-0162",
                        "CVE-2016-3351", "CVE-2016-4655", "CVE-2016-4656", "CVE-2016-4657",
                        "CVE-2016-6366", "CVE-2016-6367", "CVE-2016-3298", "CVE-2019-3010",
                        "CVE-2016-3393", "CVE-2016-7256", "CVE-2016-1010", "CVE-2016-0984",
                        "CVE-2016-0034", "CVE-2015-0310", "CVE-2015-0016", "CVE-2015-0071",
                        "CVE-2015-2360", "CVE-2015-2425", "CVE-2015-1769", "CVE-2015-4495",
                        "CVE-2015-8651", "CVE-2015-6175", "CVE-2015-1671", "CVE-2014-4148",
                        "CVE-2014-8439", "CVE-2014-4123", "CVE-2014-0546", "CVE-2014-2817",
                        "CVE-2014-4077", "CVE-2014-3153", "CVE-2013-7331", "CVE-2013-3993",
                        "CVE-2013-3896", "CVE-2013-2423", "CVE-2013-0431", "CVE-2013-0422",
                        "CVE-2013-0074", "CVE-2012-1710", "CVE-2010-1428", "CVE-2010-0840",
                        "CVE-2010-0738", "CVE-2022-26134", "CVE-2022-31460", "CVE-2019-7195",
                        "CVE-2019-7194", "CVE-2019-7193", "CVE-2019-7192", "CVE-2019-5825",
                        "CVE-2019-15271", "CVE-2018-6065", "CVE-2018-4990", "CVE-2018-17480",
                        "CVE-2018-17463", "CVE-2017-6862", "CVE-2017-5070", "CVE-2017-5030",
                        "CVE-2016-5198", "CVE-2016-1646", "CVE-2013-1331", "CVE-2012-5054",
                        "CVE-2012-4969", "CVE-2012-1889", "CVE-2012-0767", "CVE-2012-0754",
                        "CVE-2012-0151", "CVE-2011-2462", "CVE-2011-0609", "CVE-2010-2883",
                        "CVE-2010-2572", "CVE-2010-1297", "CVE-2009-4324", "CVE-2009-3953",
                        "CVE-2009-1862", "CVE-2009-0563", "CVE-2009-0557", "CVE-2008-0655",
                        "CVE-2007-5659", "CVE-2006-2492", "CVE-2021-38163", "CVE-2016-2386",
                        "CVE-2016-2388", "CVE-2022-30190", "CVE-2022-29499", "CVE-2021-30533",
                        "CVE-2021-4034", "CVE-2021-30983", "CVE-2020-3837", "CVE-2020-9907",
                        "CVE-2019-8605", "CVE-2018-4344", "CVE-2022-26925", "CVE-2022-22047",
                        "CVE-2022-26138", "CVE-2022-27924", "CVE-2022-34713", "CVE-2022-30333",
                        "CVE-2022-27925", "CVE-2022-37042", "CVE-2022-22536", "CVE-2022-32894",
                        "CVE-2022-32893", "CVE-2022-2856", "CVE-2022-26923", "CVE-2022-21971",
                        "CVE-2017-15944", "CVE-2022-0028", "CVE-2022-26352", "CVE-2022-24706",
                        "CVE-2022-24112", "CVE-2022-22963", "CVE-2022-2294", "CVE-2021-39226",
                        "CVE-2021-38406", "CVE-2021-31010", "CVE-2020-36193", "CVE-2020-28949",
                        "CVE-2022-3075", "CVE-2022-28958", "CVE-2022-27593", "CVE-2022-26258",
                        "CVE-2020-9934", "CVE-2018-7445", "CVE-2018-6530", "CVE-2018-2628",
                        "CVE-2018-13374", "CVE-2017-5521", "CVE-2011-4723", "CVE-2011-1823",
                        "CVE-2022-37969", "CVE-2022-32917", "CVE-2022-40139", "CVE-2013-6282",
                        "CVE-2013-2597", "CVE-2013-2596", "CVE-2013-2094", "CVE-2010-2568",
                        "CVE-2022-35405", "CVE-2022-3236", "CVE-2022-41082", "CVE-2022-41040",
                        "CVE-2022-36804", "CVE-2022-40684", "CVE-2022-41033", "CVE-2022-41352",
                        "CVE-2021-3493", "CVE-2020-3433", "CVE-2020-3153", "CVE-2018-19323",
                        "CVE-2018-19322", "CVE-2018-19321", "CVE-2018-19320", "CVE-2022-42827",
                        "CVE-2022-3723", "CVE-2022-41091", "CVE-2022-41073", "CVE-2022-41125",
                        "CVE-2022-41128", "CVE-2021-25337", "CVE-2021-25369", "CVE-2021-25370",
                        "CVE-2022-41049", "CVE-2021-35587", "CVE-2022-4135", "CVE-2022-4262",
                        "CVE-2022-42475", "CVE-2022-44698", "CVE-2022-27518", "CVE-2022-26500",
                        "CVE-2022-26501", "CVE-2022-42856", "CVE-2018-5430", "CVE-2018-18809",
                        "CVE-2022-41080", "CVE-2023-21674", "CVE-2022-44877", "CVE-2022-47966",
                        "CVE-2017-11357", "CVE-2022-21587", "CVE-2023-22952", "CVE-2015-2291",
                        "CVE-2022-24990", "CVE-2023-0669", "CVE-2023-21715", "CVE-2023-23376",
                        "CVE-2023-23529", "CVE-2023-21823", "CVE-2022-46169", "CVE-2022-47986",
                        "CVE-2022-41223", "CVE-2022-40765", "CVE-2022-36537", "CVE-2022-28810",
                        "CVE-2022-33891", "CVE-2022-35914", "CVE-2021-39144", "CVE-2020-5741",
                        "CVE-2023-23397", "CVE-2023-24880", "CVE-2022-41328", "CVE-2023-26360",
                        "CVE-2013-3163", "CVE-2017-7494", "CVE-2022-42948", "CVE-2022-39197",
                        "CVE-2021-30900", "CVE-2022-38181", "CVE-2023-0266", "CVE-2022-3038",
                        "CVE-2022-22706", "CVE-2022-27926", "CVE-2021-27876", "CVE-2021-27877",
                        "CVE-2021-27878", "CVE-2019-1388", "CVE-2023-26083", "CVE-2023-28205",
                        "CVE-2023-28206", "CVE-2023-28252", "CVE-2023-20963", "CVE-2023-29492",
                        "CVE-2019-8526", "CVE-2023-2033"]}


def mock_download_extract_zip(url, last_modified_old=None):
    mocked_data = None
    if url == "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip":
        mocked_data = NVD_DATA, NVD_DATA_2023_FILE_LAST_MODIFIED
    return mocked_data


def mock_get_kevc_local_data(bucket_name, file_name, storage_type):
    mocked_data = KEVC_STORED_DATA
    return mocked_data


@mock_environment_variables(BUCKET_NAME=BUCKET_NAME, STORAGE_TYPE=STORAGE_TYPE)
@mock_s3
def test_ssvc_recommendations(mocker):
    if os.environ['STORAGE_TYPE'] == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_download_extract_zip(_url, last_modified_old))
    mocker.patch.object(kevc_helper, 'get_kevc_local_data',
                        side_effect=lambda bucket_name, file_name, storage_type: mock_get_kevc_local_data(
                            bucket_name, file_name, storage_type))

    NVD_DATA["CVE_Items"] = read_from_json_file(["rapticoressvc", "test", "sample_vulnerabilities_cve_nvd_data.json"])
    update_nvd_data()
    update_kevc_data()

    # sample 01
    asset_id = "arn:aws:ec2:ca-central-1:537080276406:instance/i-0755fe20cad8a09e0"
    cve_list = ["CVE-2022-37967"]
    public_status = "private"
    environment = "production"
    asset_type = "compute"
    asset_criticality = "high"
    expected = {"asset": "arn:aws:ec2:ca-central-1:537080276406:instance/i-0755fe20cad8a09e0",
                "description": "Windows Kerberos Elevation of Privilege Vulnerability",
                "cve": ["CVE-2022-37967"], "vulnerability_score": 7.2,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "asset_type": "compute",
                "environment": "production", "public_status": "private", "asset_criticality": "high",
                "ssvc_rec": "schedule"}

    actual = ssvc_recommendations(asset_id, cve_list, public_status, environment, asset_type, asset_criticality)
    assert actual == expected

    # sample 02
    asset_id = "arn:aws:ec2:us-west-2:123456789:instance/i-0ee2ad"
    cve_list = ["CVE-2021-27104"]
    public_status = "public"
    environment = "production"
    asset_type = "None"
    asset_criticality = "critical"
    expected = {"asset": "arn:aws:ec2:us-west-2:123456789:instance/i-0ee2ad",
                "description": "Accellion FTA 9_12_370 and earlier is affected by OS command execution via a crafted "
                               "POST request to various admin endpoints. The fixed version is FTA_9_12_380 and later.",
                "cve": ["CVE-2021-27104"], "vulnerability_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "asset_type": "None",
                "environment": "production", "public_status": "public", "asset_criticality": "critical",
                "ssvc_rec": "act_now"}

    actual = ssvc_recommendations(asset_id, cve_list, public_status, environment, asset_type, asset_criticality)
    assert actual == expected


@mock_environment_variables(BUCKET_NAME=BUCKET_NAME, STORAGE_TYPE=STORAGE_TYPE)
@mock_s3
def test_sample_vulnerabilities(mocker):
    if os.environ['STORAGE_TYPE'] == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_download_extract_zip(_url, last_modified_old))
    mocker.patch.object(kevc_helper, 'get_kevc_local_data',
                        side_effect=lambda bucket_name, file_name, storage_type: mock_get_kevc_local_data(
                            bucket_name, file_name, storage_type))

    NVD_DATA["CVE_Items"] = read_from_json_file(["rapticoressvc", "test", "sample_vulnerabilities_cve_nvd_data.json"])
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
            "vul_details": row_data["cve_number"].strip() if row_data.get("cve_number").strip() != "None" else
            row_data.get("vul_severity").strip(),
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

import os

from moto import mock_s3
from rapticoressvc import nvd_data_helper
from rapticoressvc.nvd_data_helper import download_nvd_record
from rapticoressvc.nvd_data_helper import get_modification_timestamps
from rapticoressvc.nvd_data_helper import get_nvd_data
from rapticoressvc.nvd_data_helper import get_nvd_file
from rapticoressvc.nvd_data_helper import update_modification_timestamps
from rapticoressvc.nvd_data_helper import update_nvd_data
from rapticoressvc.nvd_data_helper import update_nvd_record
from rapticoressvc.storage_helpers.s3_helper import get_s3_client
from rapticoressvc.svcc_constants import STORAGE_S3
from rapticoressvc.test.testing_helper import mock_environment_variables

BUCKET_NAME = "test_bucket_ssvc"
STORAGE_TYPE = "s3"
REGION = "us-west-2"
TIMESTAMPS_FILE_NAME = "modification_timestamps"
MODIFICATION_TIMESTAMPS = {'a': 1, 'b': 2}
CVE = "CVE-999-123"
CVE_DATA = "some cve data"

NVD_DATA_2023 = {
    "CVE_data_type": "CVE",
    "CVE_data_format": "MITRE",
    "CVE_data_version": "4.0",
    "CVE_data_numberOfCVEs": "3796",
    "CVE_data_timestamp": "2023-03-31T07:00Z",
    "CVE_Items": [
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2023-0001",
                    "ASSIGNER": "psirt@paloaltonetworks.com"
                },
                "problemtype": {
                    "problemtype_data": [{
                        "description": [{
                            "lang": "en",
                            "value": "CWE-319"
                        }]
                    }]
                },
                "references": {
                    "reference_data": [{
                        "url": "https://security.paloaltonetworks.com/CVE-2023-0001",
                        "name": "https://security.paloaltonetworks.com/CVE-2023-0001",
                        "refsource": "MISC",
                        "tags": ["Vendor Advisory"]
                    }]
                },
                "description": {
                    "description_data": [{
                        "lang": "en",
                        "value": "An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent."
                    }]
                }
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [{
                    "operator": "AND",
                    "children": [{
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [{
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:critical_environment:*:*:*",
                            "versionStartIncluding": "7.5",
                            "versionEndExcluding": "7.5.101",
                            "cpe_name": []
                        }]
                    }, {
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [{
                            "vulnerable": False,
                            "cpe23Uri": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                            "cpe_name": []
                        }]
                    }],
                    "cpe_match": []
                }]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "LOCAL",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "HIGH",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 6.7,
                        "baseSeverity": "MEDIUM"
                    },
                    "exploitabilityScore": 0.8,
                    "impactScore": 5.9
                }
            },
            "publishedDate": "2023-02-08T18:15Z",
            "lastModifiedDate": "2023-02-18T20:41Z"
        },
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2023-0002",
                    "ASSIGNER": "psirt@paloaltonetworks.com"
                },
                "problemtype": {
                    "problemtype_data": [{
                        "description": [{
                            "lang": "en",
                            "value": "NVD-CWE-Other"
                        }]
                    }]
                },
                "references": {
                    "reference_data": [{
                        "url": "https://security.paloaltonetworks.com/CVE-2023-0002",
                        "name": "https://security.paloaltonetworks.com/CVE-2023-0002",
                        "refsource": "MISC",
                        "tags": ["Vendor Advisory"]
                    }]
                },
                "description": {
                    "description_data": [{
                        "lang": "en",
                        "value": "A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to execute privileged cytool commands that disable or uninstall the agent."
                    }]
                }
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [{
                    "operator": "AND",
                    "children": [{
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [{
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "5.0",
                            "versionEndExcluding": "5.0.12.22203",
                            "cpe_name": []
                        }, {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xdr_agent:*:*:*:*:critical_environment:*:*:*",
                            "versionStartIncluding": "7.5",
                            "versionEndIncluding": "7.5.101",
                            "cpe_name": []
                        }]
                    }, {
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [{
                            "vulnerable": False,
                            "cpe23Uri": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                            "cpe_name": []
                        }]
                    }],
                    "cpe_match": []
                }]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "LOCAL",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "LOW",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 7.8,
                        "baseSeverity": "HIGH"
                    },
                    "exploitabilityScore": 1.8,
                    "impactScore": 5.9
                }
            },
            "publishedDate": "2023-02-08T18:15Z",
            "lastModifiedDate": "2023-02-18T20:45Z"
        },
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2023-0003",
                    "ASSIGNER": "psirt@paloaltonetworks.com"
                },
                "problemtype": {
                    "problemtype_data": [{
                        "description": [{
                            "lang": "en",
                            "value": "CWE-610"
                        }]
                    }]
                },
                "references": {
                    "reference_data": [{
                        "url": "https://security.paloaltonetworks.com/CVE-2023-0003",
                        "name": "https://security.paloaltonetworks.com/CVE-2023-0003",
                        "refsource": "MISC",
                        "tags": ["Vendor Advisory"]
                    }]
                },
                "description": {
                    "description_data": [{
                        "lang": "en",
                        "value": "A file disclosure vulnerability in the Palo Alto Networks Cortex XSOAR server software enables an authenticated user with access to the web interface to read local files from the server."
                    }]
                }
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [{
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.8.0:3261002:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.6.0:2585049:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.6.0:2889656:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.6.0:3049220:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.6.0:3124193:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.8.0:176620:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "6.10.0",
                        "versionEndExcluding": "6.10.0.185964",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.9.0:177754:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:paloaltonetworks:cortex_xsoar:6.9.0:130766:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "LOW",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "NONE",
                        "baseScore": 6.5,
                        "baseSeverity": "MEDIUM"
                    },
                    "exploitabilityScore": 2.8,
                    "impactScore": 3.6
                }
            },
            "publishedDate": "2023-02-08T18:15Z",
            "lastModifiedDate": "2023-02-18T20:45Z"
        },
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2023-0012",
                    "ASSIGNER": "cna@sap.com"
                },
                "problemtype": {
                    "problemtype_data": [{
                        "description": [{
                            "lang": "en",
                            "value": "CWE-284"
                        }]
                    }]
                },
                "references": {
                    "reference_data": [{
                        "url": "https://launchpad.support.sap.com/#/notes/3276120",
                        "name": "https://launchpad.support.sap.com/#/notes/3276120",
                        "refsource": "MISC",
                        "tags": ["Permissions Required", "Vendor Advisory"]
                    }, {
                        "url": "https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html",
                        "name": "https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html",
                        "refsource": "MISC",
                        "tags": ["Vendor Advisory"]
                    }]
                },
                "description": {
                    "description_data": [{
                        "lang": "en",
                        "value": "In SAP Host Agent (Windows) - versions 7.21, 7.22, an attacker who gains local membership to SAP_LocalAdmin could be able to replace executables with a malicious file that will be started under a privileged account. Note that by default all user members of SAP_LocaAdmin are denied the ability to logon locally by security policy so that this can only occur if the system has already been compromised."
                    }]
                }
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [{
                    "operator": "AND",
                    "children": [{
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [{
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:sap:host_agent:7.21:*:*:*:*:*:*:*",
                            "cpe_name": []
                        }, {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:sap:host_agent:7.22:*:*:*:*:*:*:*",
                            "cpe_name": []
                        }]
                    }, {
                        "operator": "OR",
                        "children": [],
                        "cpe_match": [{
                            "vulnerable": False,
                            "cpe23Uri": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                            "cpe_name": []
                        }]
                    }],
                    "cpe_match": []
                }]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "LOCAL",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "HIGH",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 6.7,
                        "baseSeverity": "MEDIUM"
                    },
                    "exploitabilityScore": 0.8,
                    "impactScore": 5.9
                }
            },
            "publishedDate": "2023-01-10T03:15Z",
            "lastModifiedDate": "2023-01-13T17:59Z"
        },
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2023-0013",
                    "ASSIGNER": "cna@sap.com"
                },
                "problemtype": {
                    "problemtype_data": [{
                        "description": [{
                            "lang": "en",
                            "value": "CWE-79"
                        }]
                    }]
                },
                "references": {
                    "reference_data": [{
                        "url": "https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html",
                        "name": "https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html",
                        "refsource": "MISC",
                        "tags": ["Vendor Advisory"]
                    }, {
                        "url": "https://launchpad.support.sap.com/#/notes/3283283",
                        "name": "https://launchpad.support.sap.com/#/notes/3283283",
                        "refsource": "MISC",
                        "tags": ["Permissions Required", "Vendor Advisory"]
                    }]
                },
                "description": {
                    "description_data": [{
                        "lang": "en",
                        "value": "The ABAP Keyword Documentation of SAP NetWeaver Application Server - versions 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, for ABAP and ABAP Platform does not sufficiently encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability. On successful exploitation an attacker can cause limited impact on confidentiality and integrity of the application."
                    }]
                }
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [{
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:702:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:750:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:752:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:753:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:754:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:755:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:756:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:731:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:740:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:751:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:757:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "REQUIRED",
                        "scope": "CHANGED",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "LOW",
                        "availabilityImpact": "NONE",
                        "baseScore": 6.1,
                        "baseSeverity": "MEDIUM"
                    },
                    "exploitabilityScore": 2.8,
                    "impactScore": 2.7
                }
            },
            "publishedDate": "2023-01-10T03:15Z",
            "lastModifiedDate": "2023-01-13T18:00Z"
        },
        {
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": "4.0",
                "CVE_data_meta": {
                    "ID": "CVE-2023-0014",
                    "ASSIGNER": "cna@sap.com"
                },
                "problemtype": {
                    "problemtype_data": [{
                        "description": [{
                            "lang": "en",
                            "value": "CWE-294"
                        }]
                    }]
                },
                "references": {
                    "reference_data": [{
                        "url": "https://launchpad.support.sap.com/#/notes/3089413",
                        "name": "https://launchpad.support.sap.com/#/notes/3089413",
                        "refsource": "MISC",
                        "tags": ["Permissions Required", "Vendor Advisory"]
                    }, {
                        "url": "https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html",
                        "name": "https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html",
                        "refsource": "MISC",
                        "tags": ["Vendor Advisory"]
                    }]
                },
                "description": {
                    "description_data": [{
                        "lang": "en",
                        "value": "SAP NetWeaver ABAP Server and ABAP Platform - versions SAP_BASIS 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, KERNEL 7.22, 7.53, 7.77, 7.81, 7.85, 7.89, KRNL64UC 7.22, 7.22EXT, 7.53, KRNL64NUC 7.22, 7.22EXT, creates information about system identity in an ambiguous format. This could lead to capture-replay vulnerability and may be exploited by malicious users to obtain illegitimate access to the system."
                    }]
                }
            },
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [{
                    "operator": "OR",
                    "children": [],
                    "cpe_match": [{
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:702:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:700:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:701:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:710:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:711:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:730:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:731:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:740:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:750:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:751:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:752:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:753:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:754:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:755:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:756:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap:757:*:*:*:sap_basis:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_kernel:7.22:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_kernel:7.53:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_kernel:7.77:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_kernel:7.81:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_kernel:7.85:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_kernel:7.89:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_krnl64nuc:7.22:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_krnl64nuc:7.22ext:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_krnl64uc:7.22:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_krnl64uc:7.22ext:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }, {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:sap:netweaver_application_server_abap_krnl64uc:7.53:*:*:*:*:*:*:*",
                        "cpe_name": []
                    }]
                }]
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9
                }
            },
            "publishedDate": "2023-01-10T04:15Z",
            "lastModifiedDate": "2023-02-09T15:15Z"
        },
    ]
}
NVD_DATA_2023_FILE_LAST_MODIFIED = "last_modified_date_for_2023_data_file"


@mock_environment_variables(BUCKET_NAME=BUCKET_NAME, STORAGE_TYPE=STORAGE_TYPE)
@mock_s3
def test_modification_timestamps_s3():
    if os.environ['STORAGE_TYPE'] == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    update_modification_timestamps(BUCKET_NAME, TIMESTAMPS_FILE_NAME, MODIFICATION_TIMESTAMPS, STORAGE_TYPE)
    actual = get_modification_timestamps(BUCKET_NAME, TIMESTAMPS_FILE_NAME, STORAGE_TYPE)
    expected = MODIFICATION_TIMESTAMPS
    assert actual == expected


@mock_environment_variables(BUCKET_NAME=BUCKET_NAME, STORAGE_TYPE=STORAGE_TYPE)
@mock_s3
def test_cve_nvd_record_s3():
    if os.environ['STORAGE_TYPE'] == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    cve_nvd_data = {CVE: CVE_DATA}
    s3_client = STORAGE_TYPE == STORAGE_S3 and get_s3_client()
    args = dict(bucket_name=BUCKET_NAME, s3_client=s3_client, storage_type=STORAGE_TYPE)
    update_nvd_record(cve_nvd_data, args)
    actual = download_nvd_record(CVE, args)
    expected = {CVE: CVE_DATA}
    assert actual == expected


def mock_download_extract_zip(url, last_modified_old=None):
    mocked_data = None
    if url == "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip":
        mocked_data = NVD_DATA_2023, NVD_DATA_2023_FILE_LAST_MODIFIED
    return mocked_data


def test_get_nvd_file(mocker):
    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_download_extract_zip(_url, last_modified_old))
    url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{2023}.json.zip'
    actual, _ = get_nvd_file(url, None)
    expected = NVD_DATA_2023
    assert actual == expected


@mock_environment_variables(BUCKET_NAME=BUCKET_NAME, STORAGE_TYPE=STORAGE_TYPE)
@mock_s3
def test_update_nvd_data_s3(mocker):
    if os.environ['STORAGE_TYPE'] == "s3":
        get_s3_client().create_bucket(Bucket=BUCKET_NAME, CreateBucketConfiguration={'LocationConstraint': REGION})
    mocker.patch.object(nvd_data_helper, 'download_extract_zip',
                        side_effect=lambda _url, last_modified_old: mock_download_extract_zip(_url, last_modified_old))
    cve_list = ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003", "CVE-2023-0012", "CVE-2023-0013", "CVE-2023-0014"]
    expected_timestamps = {
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip': NVD_DATA_2023_FILE_LAST_MODIFIED,
        'CVE-2023-0001': '2023-02-18T20:41Z', 'CVE-2023-0002': '2023-02-18T20:45Z',
        'CVE-2023-0003': '2023-02-18T20:45Z', 'CVE-2023-0012': '2023-01-13T17:59Z',
        'CVE-2023-0013': '2023-01-13T18:00Z', 'CVE-2023-0014': '2023-02-09T15:15Z'}

    update_nvd_data()
    actual_timestamps = get_modification_timestamps(BUCKET_NAME, TIMESTAMPS_FILE_NAME, STORAGE_TYPE)
    cve_list_nvd_data = get_nvd_data(cve_list)
    assert actual_timestamps == expected_timestamps
    assert all(cve_list_nvd_data.get(cve) for cve in cve_list)

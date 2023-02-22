SSVC Ore Miner
========================

**Stakeholder-specific Vulnerability Categorization(SSVC) Ore Miner**


The Stakeholder-specific Vulnerability Categorization (SSVC) is a system for prioritizing actions during vulnerability management. SSVC aims to avoid one-size-fits-all solutions in favor of a modular decision-making system with clearly defined and tested parts that vulnerability managers can select and use as appropriate to their context.

SSVC Ore Miner extends and simplifies that work by automating the process of calculating patch priority. A known shortcoming of the Common Vulnerability Scoring System(CVSS) is that it lacks the context of the vulnerable asset. Risk-based prioritization does not take into account real-life consequences. Deferring low-priority systems with critically actively exploited vulnerabilities with the rapidly changing state of the asset. SSVC aims to improve on those methods by using asset context and vulnerability intelligence to make informed decisions that can be backed up by well-understood logic. 

The decision criteria are included for inspection, modification, and updates and can be extended to meet specific use cases. 


By contextualizing the vulnerability in the asset, we can improve prioritization and security outcomes which can help security teams focus on the vulnerabilities that can lead to a compromise. The context for the vulnerability and asset is created through the following matrix: 

**1 - Exploitation:** 
Checks for the availability of the exploit and its status using Open Source threat intelligence feeds. An exploit can be "active", "PoC" or "None"

**2 - Exposure:** 
Checks the likelihood of exposure if the exploit is used against a vulnerable asset. Exposure can be "unavoidable", " probable" or "unlikely"

**3 - Utility:** Checks for utility/ease-of-use of vulnerability against the vulnerability asset. The utility considers whether the exploit is active, whether it is network-based or local and requires user interaction and discoverability of the vulnerable asset(public, private, etc). Utility can be "effortless", "complex", or "laborious"

**4 - Impact:** Impact takes into account environment(production, non-production), asset type(compute, storage, etc) and asset criticality(critical to business, storage of sensitive data). Based on these values Impact can be "very high", "high", "medium" or "low"


The prioritization matrix uses the above vector to produce a patch priority. The patch priority can be:

https://github.com/CERTCC/SSVC
| Patch Priority | Description                                                                                                                                                            |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| act_now        | Critical risk of compromise, the production/critical asset is open to public, exploit is effective and can be used with minimum skills to create a significant impact. |
| out-of-cycle   | Increased risk of compromise patch ahead of the regular patching schedule                                                                                              |
| schedule       | Follow regular patching schedule for patch                                                                                                                             |
| defer          | Can be deferred                                                                                                                                                        |
| review          | New or yet undisclosed vulnerability - a CVSS vector has not been assigned for this vulnerability.                                                                    |

---------------

**SSVC Ore Miner Internals**


***Opensource Threat Intelligence:***
Ore Miner starts by pulling in Known Exploitable Vulnerability Catalog and NVD vulnerability Data from CISA and NIST. This data is used to check for exploitability status of the CVE and analysis of the CVSS score. The Ore Miner will still recommend Remediation Prirotization but it will not be Asset Context Aware - this takes into account whether the exploitate is an RCE or whether it requires User interaction. These factors are used to calculate the Exploitability and Utility of the vulnerability. 

***Asset Context***
If available the Asset Context is then used to further Prioritize. A decision tree is used to calculated Exposure, Utility and Impact. Each Vector is independently calculated. MITRE ATT&CK(R) Matrix for cloud is used to to map first four stages of Attack - Reconnaniness, Resource Development, Initial Access and Execution - for each asset first 4 stages are calculated in the context of the vulnerability. 
https://attack.mitre.org/matrices/enterprise/

***Decision Tree***
Each vector is calculated independently to create a query for the final Decision tree. This returns the Vulnerability Prioritization for each vulnerability in the context of the asset. 


***Usage***:
```commandline
ssvc_ore.py [-h] [--single | --datafile] [-cn CVE_NUMBER] [-p {public,public_restricted,private,None}] [-e {production,non_production,None}]
[-a {db,compute,storage,None,network}] [-s {critical,high,medium,low}] [--file FILE] [-v]
```


***Optional Arguments***:

`-h, --help show this help message` 

`--single Parameter based entry`

`--datafile csv file upload - use --file option`

`-id, --asset_id Asset Identifier(optional)`

`-cn CVE_NUMBER, --cve_number CVE_NUMBER CVE number for the vulnerability`

`-p {public,public_restricted,private,None} --public_status {public,public_restricted,private,None} Public Status, allowed values: public, public_restricted, private`

`-vs, {critical,high,medium,low} --vul_severity Vulnerability Severity where CVE Number is not available. CVE takes precedence`

`-e {production,non_production,None}, --environment {production,non_production,None} Environment for the asset. Choices: production, non_production, None -a {DB,Computer,Storage,None}`

`--assetType {db,Computer,Storage,None, network} Asset Type allowed values. Choices: db, compute, storage, None, network`

`-s {critical,high,medium,low}, --criticality {critical,high,medium,low} Criticality Business value of asset. Choices: critical, high, medium, low`

`--file FILE Provide a vulnerability/host via stdin (e.g. through piping) or --file`

`-v, --verbose Increase output verbosity`

***Example***

Example of using sample vulnerability data file in csv

```shell
cd path/to/ssvc_ore_minor
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt --upgrade
export PYTHONPATH=.
python3 rapticoressvc/ssvc_ore.py --datafile --file ./rapticoressvc/data_vulnerability.csv -v 
```

***Publish the package***
1. Update the version in pyproject.toml
2. ```shell
    python setup.py sdist bdist_wheel
   // To upload to testpypi
    python -m twine upload --repository testpypi dist/* 
   // To upload to pypi
    python -m twine upload dist/*
    ```
Further details about publishing can be found [here](https://towardsdatascience.com/how-to-publish-a-python-package-to-pypi-7be9dd5d6dcd)

***Use as a package***
```shell
pip install rapticoressvc
```
```shell
from rapticoressvc import ssvc_recommendations

ssvc_recommendations(asset_id, cve_number_or_severity, public_status, environment, asset_type, asset_criticality)
```
Based on the initial work done at

@inproceedings{spring2020ssvc, title={Prioritizing vulnerability response: {A} stakeholder-specific vulnerability
categorization}, author={Jonathan M Spring and Eric Hatleback and Allen D. Householder and Art Manion and Deana Shick},
address={Brussels, Belgium}, year={2020}, month = dec, booktitle = {Workshop on the Economics of Information Security} }


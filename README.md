Stakeholder Specific Vulnerability Categorization Ore Miner
========================

SSVC

The Stakeholder-specific Vulnerability Categorization (SSVC) is a system for prioritizing actions during vulnerability
management. SSVC aims to avoid one-size-fits-all solutions in favor of a modular decision-making system with clearly
defined and tested parts that vulnerability managers can select and use as appropriate to their context.

SSVC Ore Miner extends and simplifies that work by automating the whole process of calculating patch priority. Common
Vulnerability Scoring System(CVSS) does not address the context of the vulnerable asset. By contextualizing the
vulnerability in the asset we are able to produce much better prioritization and security outcomes that can help
security teams focus on the vulnerabiliies that can lead to a compromise. Context for the vulnerability and asset is
build by measuring the following vectors:

1 - Exploitation:
Checks for the availability of the exploit and its status using Opensoucre threat intelligence feeds. An exploit can
be "active", "PoC" or "None"
2 - Exposure:
Checks of the likelihood of expoure if the exploit is used against a vulnerable asset. Exporure can be "unavoidable", "
probable" or "unlikely"
3 - Utility:
Checks for utility/ease of use of vulnerability against the vulnerability asset. Utility takes into account whether the
exploit is active, whether it is network based or local, requires user interaction and discoverability of the vulnerable
asset(public, private, etc)
Utility can be "effortless", "complex", or "laborious"
4 - Impact:
Checks for the impact if the vulnerability is successfully exploited by taking into account environment(production,
non-production), asset type(compute, stroage, ect) and asset criticality(critical to business, holds sensitive data)
Impact can be "very high", "high", "medium" or "low"

The vectors are independently calculated and feed to to prioritization matrix to produce a patch priority. The patch
priority can be:

| Command | Description |
| --- | --- |
| Patch Priority | Description |
| act_now | Critical risk of compromise the production/critical asset is open to public, exploit is effective and can be used with minimum skills to create a significant impact.|
| out-of-cycle | Increased risk of compromise patch ahead of the regular patching schedule |
| schedule | Follow regular patching schedule for patch |
| defer | Can be deferred |

---------------

usage:
'''
ssvc_ore.py [-h] [--single | --datafile] [-cn CVE_NUMBER] [-p {public,public_restricted,private,None}] [-e {production,non_production,None}]
[-a {DB,Computer,Storage,None}] [-s {critical,high,medium,low}] [--file FILE] [-v]
'''



optional arguments:
-h, --help show this help message and exit --single Parameter based entry --datafile csv file upload - use --file option

`-cn CVE_NUMBER, --cve_number CVE_NUMBER CVE number for the vulnerability -p {public,public_restricted,private,None}, --public_status {public,public_restricted,private,None} Public Status allowed values. Choices: public, public_restricted, private -e {production,non_production,None}, --environment {production,non_production,None} Environment for the asset. Choices: production, non_production, None -a {DB,Computer,Storage,None}, --assetType {DB,Computer,Storage,None} Asset Type allowed values. Choices: DB, Compute, Storage, None -s {critical,high,medium,low}, --criticality {critical,high,medium,low} Criticality Business value of asset. Choices: critical, high, medium, low --file FILE Provide a vulnerability/host via stdin (e.g. through piping) or --file -v, --verbose Increase output verbosity`

Example of using sample vulnerability data file in csv

`cd src python3 ./ssvc/ssvc_ore.py --datafile --file ./ssvc/data/csvs/data_vulnerability.csv -v`

Based on the initial work done at

@inproceedings{spring2020ssvc, title={Prioritizing vulnerability response: {A} stakeholder-specific vulnerability
categorization}, author={Jonathan M Spring and Eric Hatleback and Allen D. Householder and Art Manion and Deana Shick},
address={Brussels, Belgium}, year={2020}, month = dec, booktitle = {Workshop on the Economics of Information Security} }

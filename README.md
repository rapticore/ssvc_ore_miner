# SSVC Ore Miner

## **Overview**
The **Stakeholder-Specific Vulnerability Categorization (SSVC) Ore Miner** is a tool designed to enhance vulnerability management by automating the process of calculating patch priority. It addresses the shortcomings of traditional methods like the Common Vulnerability Scoring System (CVSS) by incorporating asset context and vulnerability intelligence.

### **Why SSVC Ore Miner?**
While CVSS provides a generic risk score, it fails to consider the specific context of vulnerable assets. SSVC Ore Miner bridges this gap by:
- Accounting for the real-life implications of vulnerabilities.
- Using well-defined decision logic for prioritization.
- Allowing inspection, modification, and extension of decision criteria to fit organizational needs.

By leveraging asset context and vulnerability intelligence, the SSVC Ore Miner helps security teams focus on vulnerabilities that pose the highest risk of compromise.

---

## **Prioritization Criteria**

SSVC Ore Miner evaluates vulnerabilities using the following vectors:

1. **Exploitation:**  
   Determines the exploit's availability and status using open-source threat intelligence feeds.  
   - Possible values: `active`, `PoC`, `none`.

2. **Exposure:**  
   Assesses the likelihood of exposure if an exploit is used against a vulnerable asset.  
   - Possible values: `unavoidable`, `probable`, `unlikely`.

3. **Utility:**  
   Evaluates the ease of exploitation based on factors like network access, user interaction, and asset discoverability.  
   - Possible values: `effortless`, `complex`, `laborious`.

4. **Impact:**  
   Considers the environment (e.g., production or staging), asset type, and criticality to the business.  
   - Possible values: `very high`, `high`, `medium`, `low`.

---

## **Patch Priority Levels**
Based on the evaluation, SSVC Ore Miner assigns one of the following patch priorities:

| Patch Priority  | Description                                                                                                                                 |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| **act_now**      | Critical risk of compromise. The vulnerability affects a public-facing or critical asset, and the exploit is highly effective.             |
| **out-of-cycle** | Increased risk of compromise. Patching should occur ahead of the regular schedule.                                                          |
| **schedule**     | Follow the regular patching schedule.                                                                                                      |
| **defer**        | The risk is minimal; the patch can be delayed.                                                                                             |
| **review**       | The vulnerability is new or undisclosed, and a CVSS vector has not been assigned yet. Requires further analysis.                           |

---

## **Internals**

### **Open-Source Threat Intelligence**
- Pulls data from the Known Exploitable Vulnerability (KEV) catalog and NVD vulnerability data from CISA and NIST.
- Analyzes CVE exploitability and CVSS scores to calculate the **Exploitation** and **Utility** vectors.

### **Asset Context**
- Uses asset context to refine prioritization.
- Maps vulnerabilities to the first four stages of the MITRE ATT&CK® Matrix for Enterprise:  
  - **Reconnaissance**, **Resource Development**, **Initial Access**, and **Execution**.  
  - [MITRE ATT&CK Matrix](https://attack.mitre.org/matrices/enterprise/)

### **Decision Tree**
- Independently calculates vectors for **Exposure**, **Utility**, and **Impact**.  
- Uses these vectors to generate a query for the final decision tree, producing a prioritization result.

---

## **Usage**

### Command-Line Interface (CLI)

```bash
ssvc_ore.py [-h] [--single | --datafile] [-cn CVE_NUMBER] [-p {public,public_restricted,private,None}] 
             [-e {production,non_production,None}] [-a {db,compute,storage,None,network}] 
             [-s {critical,high,medium,low}] [--file FILE] [-v]
```

#### **Optional Arguments**:
- `-h, --help`: Show help message.
- `--single`: Parameter-based entry.
- `--datafile`: Upload vulnerabilities via a CSV file using `--file`.
- `-id, --asset_id`: Asset identifier (optional).
- `-cn, --cve_number`: CVE numbers separated by `|`.
- `-p, --public_status`: Public status of the asset (`public`, `public_restricted`, `private`, `none`).
- `-vs, --vul_severity`: Vulnerability severity (`critical`, `high`, `medium`, `low`).
- `-e, --environment`: Asset environment (`production`, `non_production`, `none`).
- `-a, --assetType`: Asset type (`db`, `compute`, `storage`, `network`, `none`).
- `-s, --criticality`: Business criticality of the asset (`critical`, `high`, `medium`, `low`).
- `--file`: Provide a CSV file for batch vulnerability input.
- `-v, --verbose`: Increase output verbosity.

---

### Example

Validate vulnerabilities using a sample CSV file:
```bash
cd path/to/ssvc_ore_miner
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt --upgrade
export PYTHONPATH=.
python3 ssvc_ore.py --datafile --file ./test/sample_vulnerabilities_data.csv -v
```

---

### Publish the Package

1. Update the version in `pyproject.toml`.
2. Build and upload to PyPI:
   ```bash
   python setup.py sdist bdist_wheel
   python -m twine upload dist/*
   ```

---

### Use as a Python Package
Install the package:
```bash
pip install rapticoressvc
```

Example:
```python
from rapticoressvc import ssvc_recommendations

ssvc_recommendations(
    asset_id="asset123",
    cve_numbers_array_or_severity=["CVE-2023-1234", "CVE-2023-5678"],
    public_status="public",
    environment="production",
    asset_type="compute",
    asset_criticality="high"
)
```

---

## **Credits**
Based on the work from:

Spring, J., Hatleback, E., Householder, A.D., Manion, A., & Shick, D. (2020).  
*"Prioritizing vulnerability response: A stakeholder-specific vulnerability categorization"*  
Presented at the Workshop on the Economics of Information Security, Brussels, Belgium.

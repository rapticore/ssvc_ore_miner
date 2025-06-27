# SSVC Ore Miner

## **Overview**
The **Stakeholder-Specific Vulnerability Categorization (SSVC) Ore Miner** is a tool designed to enhance vulnerability management by automating the process of calculating patch priority. It addresses the shortcomings of traditional methods like the Common Vulnerability Scoring System (CVSS) by incorporating asset context and vulnerability intelligence.

### **Why SSVC Ore Miner?**
While CVSS provides a generic risk score, it fails to consider the specific context of vulnerable assets. SSVC Ore Miner bridges this gap by:
- Accounting for the real-life implications of vulnerabilities.
- Using well-defined decision logic for prioritization.
- Allowing inspection, modification, and extension of decision criteria to fit organizational needs.
- **NEW**: Integrating EPSS (Exploit Prediction Scoring System) scores for enhanced risk assessment.

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

5. **EPSS Score:**  
   **NEW**: Exploit Prediction Scoring System score indicating the probability of exploitation within 30 days.
   - Provides percentile ranking and risk categorization.

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
- **NEW**: Fetches EPSS scores from FIRST.org API for enhanced exploit prediction.

### **Asset Context**
- Uses asset context to refine prioritization.
- Maps vulnerabilities to the first four stages of the MITRE ATT&CK® Matrix for Enterprise:  
  - **Reconnaissance**, **Resource Development**, **Initial Access**, and **Execution**.  
  - [MITRE ATT&CK Matrix](https://attack.mitre.org/matrices/enterprise/)

### **Decision Tree**
- Independently calculates vectors for **Exposure**, **Utility**, and **Impact**.  
- Uses these vectors to generate a query for the final decision tree, producing a prioritization result.
- **NEW**: Incorporates EPSS scores to enhance decision-making with exploit probability data.

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

### **Example Usage**

#### **Single Vulnerability Analysis**
```bash
ssvc_ore.py --single -id "web-server-01" -cn "CVE-2023-1234" -p "public" -e "production" -a "compute" -s "high" -v
```

#### **Batch Processing with CSV File**
```bash
ssvc_ore.py --datafile --file vulnerabilities.csv -v
```

#### **Using Severity Instead of CVE**
```bash
ssvc_ore.py --single -id "database-01" -vs "critical" -p "private" -e "production" -a "db" -s "critical" -v
```

### **CSV File Format**
Your CSV file should have the following columns:
```csv
asset_id,cve_number,vul_severity,public_status,environment,assetType,assetCriticality
web-server-01,CVE-2023-1234|CVE-2023-5678,None,public,production,compute,high
database-01,None,critical,private,production,db,critical
```

---

### Use as a Python Package
Install the package:
```bash
pip install rapticoressvc
```

Example:
```python
from rapticoressvc.ssvc_ore import ssvc_recommendations

# Analyze a single vulnerability
result = ssvc_recommendations(
    asset="web-server-01",
    vul_details=["CVE-2023-1234"],
    public_status="public",
    environment="production",
    asset_type="compute",
    asset_criticality="high"
)

print(f"SSVC Recommendation: {result['ssvc_rec']}")
print(f"EPSS Score: {result['epss_score']}")
print(f"EPSS Category: {result['epss_category']}")
```

---

## **Requirements**

- Python 3.9+
- Internet connection for fetching vulnerability data
- Optional: AWS credentials for S3 storage (if using S3 storage type)

---

## **Credits**
Based on the work from:

Spring, J., Hatleback, E., Householder, A.D., Manion, A., & Shick, D. (2020).  
*"Prioritizing vulnerability response: A stakeholder-specific vulnerability categorization"*  
Presented at the Workshop on the Economics of Information Security, Brussels, Belgium.

from rapticoressvc.helpers import execute_db, process_cvss_score, nvd_parser
from rapticoressvc.svcc_helper import calculate_impact, calculate_utility


def vector_calculate_exploitability(cve_number, cvss_vector):
    """
    EXPLOITATION = ["none", "PoC", "active"]
    active > PoC > none
    None: There is no evidence of active exploitation and no public proof of concept (PoC)
    of how to exploit the vulnerability.

    Public PoC: One of the following is true: (1) Typical public PoC exists in sources such as
    Metasploit or websites like ExploitDB; or (2) the vulnerability has a well-known
    method of exploitation. Some examples of condition (2) are open-source web
    proxies that serve as the PoC code for how to exploit any vulnerability in the vein
    of improper validation of Transport Layer Security (TLS) certificates, and
    Wireshark serving as a PoC for packet replay attacks on ethernet or Wi-Fi
    networks.

    Active:Shared, observable, and reliable evidence that cyber threat actors

    1 - Check CISA KEVC - check whether a CVE has an active exploit
        if yes =>> Exploitcation = active
    2 - Check NVBlib - Check whether schema has addition information
        if not CISA KEVC ==>
        Check CVSS for Exploit Code Maturity(E)
        Exploit Code Maturity (E)
        ==> Empty: None
            Unprove: E:U
            Proof-of-concept: E:P -- Explication = PoC
            Functional: E:F -- Explication = active
            High: E:H -- Explication = active
    """
    check = execute_db(cve_number)
    if check:
        exploit_status = "active"
        return exploit_status
    else:
        exploit_status = nvd_parser(cvss_vector)
        return exploit_status


def vector_calculate_exposure(score):
    """
    EXPOSURE = ["unlikely", "probable", "unavoidable"]
    unavoidable > controlled > limited
    Partial:
    One of the following is true: The exploit gives the threat actor limited control over,
    or information exposure about, the behavior of the software that contains the
    vulnerability; or the exploit gives the threat actor a low stochastic opportunity for
    total control. In this context, “low” means that the attacker cannot reasonably
    make enough attempts to overcome obstacles, either physical or security-based,
    to achieve total control. A denial-of-service attack is a form of limited control over
    the behavior of the vulnerable component.
    Partial => limited, controlled
    C:L or I:L or A:H and PR:H
    CVSS Score 0/low/medium --> 6.9 => unlikely exposure
    CVSS Score 7 --> 8.9/high == probable exposure
    CVSS Score 9 --> 10/critical == unavoidable exposure
    """
    severity_list = ["critical", "high", "medium", "low"]
    severity_priority = ["critical", "high"]
    severity_defer = ["medium", "low"]
    if score in severity_list:
        if score == "critical":
            return "unavoidable"
        elif score == "high":
            return "probable"
        elif score in severity_defer:
            return "unlikely"
    elif score:
        score = float(score)
        if score >= 9.0:
            return "unavoidable"
        elif 7.0 <= score <= 8.9:
            return "probable"
        elif score <= 6.9:
            return "unlikely"


def vector_calculate_utility(exploit, cvss_vector, public_status, score):
    """
    Effort required to use the vulnerability
    Utility = ["laborious", "complex", "effortless"]

    Effortless - point and click, little to no User Interaction - skills required minimum - easily discoverable
    Complex - Requires skills and targeting, user interaction required even if publicly accessible
    Laborious - Multiples factors, inaccessible, requires skills, user interaction etc.

    effortless > complex > laborious

    Super effective =>
    Exploit + Network Exploit(AV:N) + Publicly Access + User Interaction is NONE(UI:N)
    Exploit + Network Exploit(AV:N) + Publicly Restricted Access + User Interaction is NONE (UI:N)

    Efficient =>
    Exploit + Network Exploit(AV:N) + Publicly Access + User Interaction is REQUIRED (UI:R)
    Exploit + Network Exploit(AV:N) + Public Restricted Access + User Interaction is REQUIRED (UI:R)
    Network Exploit(AV:N) + Publicly Accessible + User Interaction is NONE(UI:N)
    Network Exploit(AV:N) + Public Restricted Accessible + User Interaction is NONE (UI:N)

    Laborious =>
    Network Exploit(AV:N) + PRIVATE + User Interaction is (UI:R)
    Network Exploit(AV:N) + PRIVATE + User Interaction is (UI:N)
    Network Exploit(AV:L) + PRIVATE + User Interaction is (UI:N)
    Network Exploit(AV:L) + PRIVATE + User Interaction is (UI:R)

    https://mitre-attack.github.io/attack-navigator/
    (1) Reconnaissance:
    the vulnerable component is not searchable or enumerable on the network,

    (2) Weaponization may require human direction for each target,

    (3) delivery may require channels that widely deployed network security configurations block, and
    Future Implementation

    (4) exploitation may be frustrated by adequate exploit-prevention techniques
    enabled by default (address space layout randomization [ASLR] is an example of
    an exploit-prevention tool).

    Steps 1-4 of the kill chain—reconnaissance, weaponization, delivery, and
    exploitation — cannot be reliably automated for this vulnerability.1 Examples for
    explanations of why each step may not be reliably automatable include:

    Steps 1-4 of the kill chain can be reliably automated. If the vulnerability
    allows unauthenticated remote code execution (RCE) or command injection, the
    response is likely yes.


    """
    severity_list = ["critical", "high", "medium", "low"]
    severity_priority = ["critical", "high"]
    attack_vector, user_interaction = None, None
    if cvss_vector:
        vector_dict = process_cvss_score(cvss_vector)
        query = {"exploit": exploit, "attack_vector": vector_dict.get("AV"), "user_interaction": vector_dict.get("UI"),
                 "public_status": public_status}
        utility = calculate_utility(query)
        return utility
    else:
        if score in severity_priority:
            attack_vector, user_interaction = "N", "N"
        else:
            attack_vector, user_interaction = "L", "R"
        query = {"exploit": exploit, "attack_vector": attack_vector, "user_interaction": user_interaction,
                 "public_status": public_status}
        utility = calculate_utility(query)
        return utility


def vector_calculate_impact(environment, asset_type, asset_criticality):
    """
    Very High, High = Environment Production - Asset Type DB, Compute, Storage, Critical, High
    High, medium, low = Environment Production - Asset Type Everything else, high, medium, low
    High = Environment Non-production - Asset Type DB, Compute, Storage, critical, high, medium, low
    High, medium, low = Environment Non-production - Asset Type Everything else, High, medium, low

    IMPACT = ["low", "medium", "high", "very high"]

    Minimal: Neither support nor essential apply. The vulnerable component may be used within the
    entities, but it is not used as a mission-essential component, nor does it provide
    impactful support to mission-essential functions.
    Support The vulnerable component only supports MEFs for two or more entities.
    Asset Criticality = ["low", "medium", "high", "critical"]

    Critical: Production Sensitive data or function - PII data, Financial or other sensitive data
    High: Production/Non-production Sensitive data or function -data not in sensitive category-
    but high importance to business
    Medium: Non-Production  - Criticality to business
    Low: Non-production - tests

    Essential: The vulnerable component directly provides capabilities that constitute at least one MEF
    for at least one entity;
    """

    query = {"Environment": environment, "AssetType": asset_type, "AssetCriticality": asset_criticality}
    vector = calculate_impact(query)
    return vector

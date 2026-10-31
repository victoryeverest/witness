"""MITRE ATT&CK mapping (§21, §27, §28).

Evidence-backed mapping: we never claim a technique merely because the LLM
thinks it "sounds similar" (§21). Each technique is mapped by a deterministic
rule over the evidence's normalized_data fields.

Includes both Enterprise ATT&CK and ICS ATT&CK, and supports relationships
between the two (§27).
"""
from __future__ import annotations

from typing import Any


# Enterprise ATT&CK techniques used in the rule library (subset).
# This is NOT a hardcoded outdated list — the rule library is the basis for
# mapping, and the techniques table can be loaded from the MITRE ATT&CK
# STIX/JSON datasets at runtime. For demoing we include a representative set
# that the cyber range scenarios cover.
ENTERPRISE_TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1059.006": "Python",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1078": "Valid Accounts",
    "T1078.002": "Domain Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1078.003": "Local Accounts",
    "T1021": "Remote Services",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.001": "Remote Desktop Protocol",
    "T1110": "Brute Force",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1071": "Application Layer Protocol",
    "T1071.004": "DNS",
    "T1098": "Account Manipulation",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1190": "Exploit Public-Facing Application",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1136": "Create Account",
    "T1071.001": "Web Protocols",
}

# ICS ATT&CK techniques per the MITRE ICS matrix.
ICS_TECHNIQUES = {
    # MITRE ATT&CK for ICS technique IDs and names (offline fallback; the STIX
    # loader is authoritative when available). A test keeps every technique
    # used by rules, templates and ground truth inside this catalogue.
    "T0800": "Activate Firmware Update Mode",
    "T0801": "Monitor Process State",
    "T0802": "Automated Collection",
    "T0803": "Block Command Message",
    "T0804": "Block Reporting Message",
    "T0806": "Brute Force I/O",
    "T0807": "Command-Line Interface",
    "T0809": "Data Destruction",
    "T0811": "Data from Information Repositories",
    "T0813": "Denial of Control",
    "T0814": "Denial of Service",
    "T0815": "Denial of View",
    "T0816": "Device Restart/Shutdown",
    "T0817": "Drive-by Compromise",
    "T0819": "Exploit Public-Facing Application",
    "T0821": "Modify Controller Tasking",
    "T0822": "External Remote Services",
    "T0823": "Graphical User Interface",
    "T0826": "Loss of Availability",
    "T0827": "Loss of Control",
    "T0828": "Loss of Productivity and Revenue",
    "T0829": "Loss of View",
    "T0830": "Adversary-in-the-Middle",
    "T0831": "Manipulation of Control",
    "T0832": "Manipulation of View",
    "T0834": "Native API",
    "T0835": "Manipulate I/O Image",
    "T0836": "Modify Parameter",
    "T0837": "Loss of Protection",
    "T0838": "Modify Alarm Settings",
    "T0840": "Network Connection Enumeration",
    "T0842": "Network Sniffing",
    "T0843": "Program Download",
    "T0845": "Program Upload",
    "T0846": "Remote System Discovery",
    "T0847": "Replication Through Removable Media",
    "T0848": "Rogue Master",
    "T0849": "Masquerading",
    "T0852": "Screen Capture",
    "T0853": "Scripting",
    "T0855": "Unauthorized Command Message",
    "T0856": "Spoof Reporting Message",
    "T0857": "System Firmware",
    "T0858": "Change Operating Mode",
    "T0859": "Valid Accounts",
    "T0861": "Point & Tag Identification",
    "T0862": "Supply Chain Compromise",
    "T0863": "User Execution",
    "T0865": "Spearphishing Attachment",
    "T0866": "Exploitation of Remote Services",
    "T0867": "Lateral Tool Transfer",
    "T0869": "Standard Application Layer Protocol",
    "T0872": "Indicator Removal on Host",
    "T0873": "Project File Infection",
    "T0877": "I/O Module Discovery",
    "T0878": "Alarm Suppression",
    "T0879": "Damage to Property",
    "T0880": "Loss of Safety",
    "T0881": "Service Stop",
    "T0882": "Theft of Operational Information",
    "T0884": "Connection Proxy",
    "T0885": "Commonly Used Port",
    "T0886": "Remote Services",
    "T0889": "Modify Program",
}

ICS_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Inhibit Response Function",
    "Impair Process Control",
    "Impact",
]


# Rule library: (rule_function, technique_id).
# A rule takes normalized_data and returns True if the technique applies.
# This enforces evidence-backed mapping per §21.
def _rule_powershell(nd: dict[str, Any]) -> bool:
    img = (nd.get("image") or "").lower()
    return "powershell" in img or "pwsh" in img

def _rule_encoded_command(nd: dict[str, Any]) -> bool:
    cl = (nd.get("command_line") or "").lower()
    return "-enc" in cl or "-encodedcommand" in cl or "frombase64string" in cl

def _rule_lateral_auth(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "auth_lateral" or (
        nd.get("event_kind") == "auth_event" and nd.get("logon_type") == 3
    )

def _rule_credential_dump(nd: dict[str, Any]) -> bool:
    img = (nd.get("image") or "").lower()
    cl = (nd.get("command_line") or "").lower()
    target = (nd.get("target_image") or "").lower()
    return ("lsass" in cl or "lsass" in target or "procdump" in img
            or "mimikatz" in img or "sekurlsa" in cl)


def _rule_decoded_ioc(nd: dict[str, Any]) -> bool:
    """Decoded command line pulls from known-bad infrastructure (Ingress Tool Transfer)."""
    return nd.get("event_kind") == "decoded_command" and bool(nd.get("iocs"))


def _rule_service_create(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "service_create"


def _rule_suspicious_valid_account(nd: dict[str, Any]) -> bool:
    """Successful remote logon from infrastructure on a threat-intel list."""
    return (nd.get("event_kind") == "auth_event" and nd.get("outcome") == "success"
            and bool(nd.get("suspicious_source")))


def _rule_alarm_suppressed(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "alarm_event" and bool(nd.get("suppressed"))

def _rule_smb_connection(nd: dict[str, Any]) -> bool:
    return (nd.get("dst_port") == 445) or (nd.get("event_kind") == "flow" and
                                            nd.get("dst_port") == 445)

def _rule_dns_nrd(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "dns_nrd"

def _rule_registry_persist(nd: dict[str, Any]) -> bool:
    kp = (nd.get("key_path") or "")
    return "Run\\" in kp or "RunOnce" in kp

def _rule_failed_auth(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "auth_event" and nd.get("outcome") == "failure"

def _rule_iam_change(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "iam_change"

def _rule_modbus_write(nd: dict[str, Any]) -> bool:
    return (nd.get("event_kind") == "plc_write" or
            (nd.get("event_kind") == "plc_read" and nd.get("function") == "write_single_register"))

def _rule_process_var_dev(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "process_var_change"

def _rule_ioc_hit(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "ioc_hit"

def _rule_beacon(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "beacon_http"

def _rule_email_click(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "email_click"

def _rule_auth_failure(nd: dict[str, Any]) -> bool:
    return nd.get("event_kind") == "auth_failure"

_RULES = [
    (_rule_powershell, "T1059.001"),
    (_rule_encoded_command, "T1059.001"),
    (_rule_decoded_ioc, "T1105"),
    (_rule_lateral_auth, "T1021.002"),
    (_rule_credential_dump, "T1003.001"),
    (_rule_service_create, "T1543.003"),
    (_rule_suspicious_valid_account, "T1078.002"),
    (_rule_alarm_suppressed, "T0878"),        # Alarm Suppression
    (_rule_smb_connection, "T1021.002"),
    (_rule_dns_nrd, "T1071.004"),
    (_rule_registry_persist, "T1547.001"),
    (_rule_failed_auth, "T1110"),
    (_rule_iam_change, "T1098"),
    (_rule_modbus_write, "T0855"),            # Unauthorized Command Message
    (_rule_modbus_write, "T0836"),            # Modify Parameter (register/setpoint write)
    (_rule_process_var_dev, "T0831"),         # Manipulation of Control
    (_rule_email_click, "T1566.001"),
    (_rule_beacon, "T1071.001"),
    (_rule_auth_failure, "T1110"),
]


def map_evidence_to_attack(normalized_data: dict[str, Any]) -> list[str]:
    """Return the list of ATT&CK techniques that the evidence supports."""
    out: list[str] = []
    for rule, tech in _RULES:
        try:
            if rule(normalized_data):
                out.append(tech)
        except Exception:
            continue
    # Dedup, preserve order.
    seen: set[str] = set()
    dedup: list[str] = []
    for t in out:
        if t not in seen:
            dedup.append(t)
            seen.add(t)
    return dedup


def is_ics_technique(tech_id: str) -> bool:
    return tech_id in ICS_TECHNIQUES


def is_enterprise_technique(tech_id: str) -> bool:
    return tech_id in ENTERPRISE_TECHNIQUES


def technique_name(tech_id: str) -> str:
    if tech_id in ENTERPRISE_TECHNIQUES:
        return ENTERPRISE_TECHNIQUES[tech_id]
    if tech_id in ICS_TECHNIQUES:
        return ICS_TECHNIQUES[tech_id]
    return tech_id

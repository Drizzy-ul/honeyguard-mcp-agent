"""Static MITRE ATT&CK technique catalog for RAG embedding.

This module provides a curated subset of MITRE ATT&CK Enterprise techniques
relevant to honeypot and network intrusion scenarios. In production this
would be populated from the full MITRE STIX feed.
"""
from __future__ import annotations

MITRE_TECHNIQUES: list[dict] = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained. "
            "Sub-techniques include password guessing, password spraying, "
            "credential stuffing, and password cracking."
        ),
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into a service specifically "
            "designed to accept remote connections, such as SSH, RDP, SMB, or VNC. "
            "The adversary may then perform actions as the logged-on user."
        ),
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on remote "
            "hosts and local network infrastructure devices, including those that may "
            "be vulnerable to remote exploitation. Port scanning is a common method."
        ),
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, "
            "scripts, or binaries. These interfaces and languages provide ways of "
            "interacting with computer systems and are a common feature across many "
            "different platforms, including Linux /bin/bash, Windows cmd.exe and PowerShell."
        ),
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may delete or modify artifacts generated within systems to "
            "remove evidence of their presence or hinder defenses. This includes "
            "clearing event logs, deleting files, and modifying timestamps."
        ),
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may inject code into processes in order to evade process-based "
            "defenses as well as possibly elevate privileges. Process injection is a "
            "method of executing arbitrary code in the address space of a separate live "
            "process."
        ),
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing command "
            "and control channel. Stolen data is encoded into the normal communications "
            "channel using the same protocol as C2 communications."
        ),
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to take advantage of a weakness in an Internet-facing "
            "computer or program using software, data, or commands in order to cause "
            "unintended or unanticipated behavior. Exploited applications are often "
            "web servers, databases, and standard services."
        ),
    },
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may maliciously modify components of a victim environment in "
            "order to hinder or disable defensive mechanisms. This not only involves "
            "attacking preventative defenses such as firewalls and anti-virus, but also "
            "detection capabilities such as SIEM and EDR solutions."
        ),
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create an account to maintain access to victim systems. "
            "With a sufficient level of access, creating such accounts may be used to "
            "establish secondary credentialed access that do not require persistent "
            "remote access tools to be deployed on the system."
        ),
    },
]

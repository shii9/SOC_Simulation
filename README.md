# 🛡️ SOC Simulation & Detection Engineering Hub
### Enterprise Threat Emulation, Endpoint Telemetry Correlation & SIEM Threat Hunting

[![Splunk Enterprise](https://img.shields.io/badge/Splunk_Enterprise-9.x%20%2F%2010.x-FF0000?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![Microsoft Sysmon](https://img.shields.io/badge/Microsoft_Sysmon-v14.1+-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-orange?style=for-the-badge&logo=mitre&logoColor=white)](https://attack.mitre.org/)
[![Sigma Rules](https://img.shields.io/badge/Sigma_Rules-HQ_Standard-blueviolet?style=for-the-badge&logo=github)](https://github.com/SigmaHQ/sigma)
[![Status](https://img.shields.io/badge/Repository-Active_Simulations-brightgreen?style=for-the-badge)](#-simulation-catalog)

---

## 📖 Overview

Welcome to the **SOC Simulation & Detection Engineering Hub**. This repository serves as a centralized, extensible repository for realistic **Security Operations Center (SOC) threat simulations**, **digital forensics investigations (DFIR)**, **purple team adversary emulation**, and **SIEM detection engineering**.

Each project within this repository models a complete real-world cyber attack lifecycle in an isolated, multi-system virtual laboratory. Telemetry is collected at the endpoint and network layers, forwarded to a centralized SIEM (**Splunk Enterprise**), analyzed through custom **Sigma Rules** and **Splunk SPL hunting queries**, and systematically mapped to the **MITRE ATT&CK Framework**.

---

## 🗂️ Simulation Catalog

| # | Simulation Project | Target Platform | Primary Focus & Attack Vectors | SIEM / Telemetry Stack | Status | Documentation Link |
|:---:|:---|:---:|:---|:---|:---:|:---:|
| **01** | **Endpoint Compromise & Credential Access** | Windows 10 / Kali Linux | Phishing lure, Meterpreter HTTP C2, Discovery, Local Admin Account, Scheduled Task SYSTEM Persistence, certutil tool staging, Mimikatz `privilege::debug` | Sysmon v14+, Windows Security Events 4688/4698/4720/4732, Splunk Enterprise | `COMPLETED` | [📁 View Project](./SOC_Investigation_Simulation_1/) |

---

## 🏗️ Repository Architecture & Standards

To ensure consistency, repeatability, and high academic/industry quality across simulations, each project follows a standardized directory structure:

```
SOC_Simulation/
├── README.md                                 <-- Global Hub & Master Catalog
├── .gitignore                                <-- Artifact & log exclusions
│
└── SOC_Investigation_Simulation_1/             <-- Simulation 01: Endpoint Compromise & Credential Access
    ├── README.md                             <-- Exhaustive technical documentation & forensic analysis
    ├── docs/
    │   ├── Splunk-SOC-Investigation-(1)-Report.docx  <-- Full technical report document
    │   └── mitre_attack_navigator_layer.json <-- Interactive ATT&CK Navigator JSON layer
    ├── assets/
    │   └── images/                           <-- Attack maps, lab architecture diagrams, lineage trees
    ├── detections/
    │   ├── sigma/                            <-- Production-ready Sigma YAML detection rules
    │   └── splunk_spl/                       <-- Optimized Splunk SPL hunting and correlation queries
    ├── artifacts/
    │   ├── iocs.csv                          <-- Machine-readable IOCs (hashes, IPs, paths, accounts)
    │   └── telemetry_matrix.csv              <-- Data sources, Event IDs, and detection mappings
    └── simulation_guide/
        └── attack_walkthrough.md             <-- Step-by-step commands to reproduce the simulation
```

---

## 🔄 Universal Detection Engineering Pipeline

Every simulation published in this repository adheres to the **Purple Team Lifecycle**:

```
 ┌──────────────────────┐
 │  Adversary Emulation │  Controlled attack execution using realistic TTPs
 └──────────┬───────────┘
            │
            ▼
 ┌──────────────────────┐
 │ Telemetry Collection │  Sysmon, Windows Event Logs, Linux Auditd, Network Sockets
 └──────────┬───────────┘
            │
            ▼
 ┌──────────────────────┐
 │    SIEM Ingestion    │  Forwarded in real time to Splunk Enterprise via Universal Forwarder
 └──────────┬───────────┘
            │
            ▼
 ┌──────────────────────┐
 │  Detection & Hunting │  Sigma rules development + SPL hunting and correlation playbooks
 └──────────┬───────────┘
            │
            ▼
 ┌──────────────────────┐
 │ ATT&CK Matrix & DFIR │  Behavioral mapping, interactive Navigator layers & remediation hardening
 └──────────────────────┘
```

---

## 🛠️ Global Prerequisites & Recommended Setup

To reproduce or adapt the simulations in this hub, the following base environment is recommended:

- **Virtualization**: VMware Workstation Pro / VirtualBox / Proxmox VE
- **Victim Endpoint**: Windows 10 Enterprise / Windows 11 Enterprise (22H2+) with Sysmon installed using a modular configuration (e.g., [SwiftOnSecurity Sysmon-Config](https://github.com/SwiftOnSecurity/sysmon-config))
- **Attacker Platform**: Kali Linux (latest rolling release) equipped with Metasploit Framework, Impacket, and standard offensive tooling
- **SIEM Platform**: Splunk Enterprise 9.x or 10.x running on a dedicated VM or host system
- **Forwarder**: Splunk Universal Forwarder installed on all monitored endpoints streaming to port `9997`

---

## ➕ How to Add a New Simulation

When adding a new simulation to this repository:
1. Create a dedicated directory under the root named after the scenario (e.g., `New_Simulation_Name/`).
2. Populate the subfolders according to the template: `docs/`, `assets/images/`, `detections/sigma/`, `detections/splunk_spl/`, `artifacts/`, `simulation_guide/`.
3. Provide a standalone, comprehensive `README.md` inside the project folder detailing the scenario, architecture, evidence, SPL queries, and remediation.
4. Update the **Simulation Catalog** table in this root `README.md`.
5. Ensure all code blocks, queries, and YAML files are validated for syntax correctness.

---

## ⚖️ Legal & Ethical Disclaimer

All content, commands, scripts, and attack simulations documented in this repository are developed strictly for **educational, defensive, and authorized research purposes only**. The techniques are intended to assist SOC analysts, security engineers, threat hunters, and blue teams in identifying and mitigating adversarial threats. Never attempt any unauthorized actions against networks or systems you do not own or have explicit written permission to test.

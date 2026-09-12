# PHOENIX

## Autonomous Enterprise Cyber Defense Platform

PHOENIX is a cybersecurity operations platform developed as an internship project. The project brings different security operations activities into one platform, including security event monitoring, detection, alert investigation, incident response, threat intelligence, vulnerability management, digital forensics, Zero Trust monitoring and automated response.

The project was developed and tested in a controlled Kali Linux security laboratory.

---

## Overview

The main goal of PHOENIX is to provide a single platform for handling the security operations lifecycle:

**Collect → Detect → Enrich → Investigate → Respond → Recover → Learn**

Instead of keeping every security function separate, PHOENIX connects security events with detections, alerts, incidents, investigations, response actions and recovery activities.

---

## Key Features

- Security Event Collection and Monitoring
- Asset Inventory
- Detection Engineering
- Alert Management
- Incident Management
- Threat Intelligence
- Alert Enrichment
- SOAR Playbooks
- Vulnerability Management
- Zero Trust Monitoring
- Identity and Access Management
- Endpoint / EDR Monitoring
- Cloud Security Monitoring
- Kubernetes Security
- Container Security
- Threat Hunting
- Digital Forensics
- Data Loss Prevention
- Risk Management
- Compliance Tracking
- Recovery Workflows
- SOC Metrics
- Security Reports
- Controlled Adversary Scenarios
- Audit Logging
- Role-Based Access Control

---

Installation
Requirements
Python 3.11+
MySQL 8+
Git
Kali Linux or another Debian-based Linux system
Clone the Repository
git clone git@github.com:Dark-Devil-Lucifer/PHOENIX.git
cd PHOENIX
Create Virtual Environment
python3 -m venv .venv
source .venv/bin/activate
Install Dependencies
pip install -r requirements.txt
Configure Environment
cp .env.example .env

Edit the environment file and configure the local MySQL connection and JWT secret.

Do not commit the .env file.

Start PHOENIX

From the project root:

PYTHONPATH="$PWD" uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

Open the application:

http://127.0.0.1:8000

API documentation:

http://127.0.0.1:8000/docs

## Security Operations Workflow

```text
                 Security Event
                       |
                       v
                Event Processing
                       |
                       v
                Detection Engine
                       |
                       v
                     Alert
                       |
                       v
             Enrichment / Investigation
                       |
                       v
                   Incident
                       |
                       v
              Response / SOAR
                       |
                       v
                 Containment
                       |
                       v
                   Recovery
                       |
                       v
             Resolution / Audit
```
Technology Stack
Frontend
HTML5
CSS3
JavaScript
Fetch API
Backend
Python
FastAPI
SQLAlchemy
Pydantic
JWT Authentication
Argon2 Password Hashing
Database
MySQL
Security Environment
Kali Linux
Burp Suite
Nmap
Wireshark
OWASP security testing methodology
Controlled security testing scenarios

Architecture
```
                    +----------------------+
                    |      SOC Analyst     |
                    |       SOC Lead       |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |     PHOENIX Web UI   |
                    |    HTML/CSS/JS       |
                    +----------+-----------+
                               |
                             REST
                               |
                               v
                    +----------------------+
                    |      FastAPI API     |
                    +----------+-----------+
                               |
          +--------------------+--------------------+
          |                    |                    |
          v                    v                    v
   Detection Engine       Threat Intel          SOAR
          |                    |                    |
          +--------------------+--------------------+
                               |
                               v
                    +----------------------+
                    |       MySQL DB       |
                    +----------------------+

Project Structure
PHOENIX/
│
├── backend/
│   ├── api/
│   ├── core/
│   ├── detection/
│   ├── intelligence/
│   ├── models/
│   ├── scenarios/
│   ├── schemas/
│   ├── services/
│   └── main.py
│
├── database/
│   ├── schema/
│   └── seeds/
│
├── detection-rules/
│
├── docs/
│   ├── evidence/
│   └── screenshots/
│
├── frontend/
│   ├── css/
│   ├── js/
│   ├── pages/
│   ├── index.html
│   └── login.html
│
├── playbooks/
│
├── tests/
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```
Author
Ajay Chouhan

Cybersecurity / Data Science

GitHub:
https://github.com/Dark-Devil-Lucifer

Project Information

Project Name: PHOENIX

Project Type: Internship Project

Category: Cybersecurity / SOC / SIEM / SOAR

Environment: Controlled Security Laboratory

Primary Language: Python

Frontend: HTML, CSS, JavaScript

Database: MySQL

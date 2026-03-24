# FalconX — Enterprise Security Audit System (ESAS)

A full-stack Flask web application for automated enterprise security auditing, compliance validation, and vulnerability management.

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the application
```bash
python app.py
```

Open http://localhost:5000 in your browser.

---

## Demo Accounts

| Role    | Username | Password    | Permissions                     |
|---------|----------|-------------|---------------------------------|
| Admin   | admin    | Admin@123   | Full access, user management    |
| Auditor | auditor  | Audit@123   | Run scans, edit rules           |
| Viewer  | viewer   | View@123    | Read-only, view reports         |

---

## Features

### Security Auditing
- **Combined Audit** — vulnerability scan + compliance check in one run
- **Compliance Audit** — ISO 27001, NIST CSF, PCI DSS, GDPR rule validation
- **Vulnerability Scan** — CVE detection, CVSS scoring, host-level findings

### Target Types
- ☁ **Cloud** — AWS IAM, S3, EC2, RDS, Lambda, VPC Security Groups
- 🖧 **Network / On-Premise** — CIDR range scanning via OpenVAS/Nmap
- 🌐 **Application** — URL/IP target, OWASP Top 10, API security

### Scan Modes
- **Manual** — trigger on demand
- **Scheduled** — daily/weekly/monthly with cron

### Reporting
- Real-time progress monitoring
- Vulnerability table with severity filtering and CVE search
- Compliance check results per framework (ISO 27001, NIST CSF)
- Executive summary with remediation priorities
- **PDF export** with full audit report (requires reportlab)

### Alerts
- Email alerts for critical/high/medium findings
- Slack webhook integration
- Configurable per-user alert preferences

### Role-Based Access Control
- Admin: full access including user management
- Auditor: run scans, edit compliance rules
- Viewer: read-only dashboard and reports

### Compliance Rule Editor
- View/edit/add/delete compliance rules per framework
- Support for ISO 27001, NIST CSF, PCI DSS, GDPR, Custom
- Check types: policy, configuration, port, patch, manual

### Dashboard
- Risk score (0–100)
- Vulnerability trend chart (Chart.js)
- Network topology map (canvas)
- Live compliance bars

---

## OpenVAS Integration (Production)

Replace `simulate_scan()` in `app.py` with real GVM/OpenVAS calls:

```python
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp

connection = TLSConnection(hostname='localhost', port=9390)
with Gmp(connection) as gmp:
    gmp.authenticate('admin', 'admin')
    task_id = gmp.create_task(name='ESAS Scan', config_id='...', target_id='...')
    gmp.start_task(task_id)
```

Install: `pip install python-gvm`

---

## AWS Integration (Production)

```python
import boto3

session = boto3.Session(aws_access_key_id=KEY, aws_secret_access_key=SECRET)
iam = session.client('iam')
s3 = session.client('s3')

# Check IAM password policy
response = iam.get_account_password_policy()

# List S3 buckets and check public access
buckets = s3.list_buckets()['Buckets']
for bucket in buckets:
    acl = s3.get_bucket_acl(Bucket=bucket['Name'])
    # Check for public grants
```

---

## Database

SQLite by default (`instance/esas.db`). For production, switch to PostgreSQL:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/esas'
```

---

## Project Structure

```
esas/
├── app.py                  # Flask app, routes, scan engine, models
├── requirements.txt
├── instance/
│   └── esas.db             # SQLite database (auto-created)
└── templates/
    ├── base.html           # Shared navbar, styles
    ├── login.html          # Login page
    ├── dashboard.html      # Main dashboard
    ├── configure.html      # Audit configuration (matches FalconX design)
    ├── reports.html        # Scan reports + PDF export
    └── settings.html       # Users, alerts, compliance rules
```

---

## Security Notes for Production

1. Change `SECRET_KEY` to a random 32-byte string
2. Use environment variables for all credentials
3. Enable HTTPS (Flask behind nginx + Let's Encrypt)
4. Switch SQLite → PostgreSQL for multi-user production use
5. Add rate limiting with Flask-Limiter
6. Enable CSRF protection with Flask-WTF

---

Built for: Sinhgad College of Engineering — ESAS Research Paper (IJIRCCE Vol 13, Nov 2025)
Authors: Dharmabhaskar Panchgalle, Jay Navale, Piyush Latne, Rohit Chavhan

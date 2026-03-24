from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import json, os, threading, time, random, sqlite3, io

app = Flask(__name__)
app.secret_key = 'esas-secret-key-change-in-production'

DB = os.path.join(os.path.dirname(__file__), 'esas.db')

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, audit_type TEXT, target_type TEXT,
            target TEXT, ports TEXT, scan_mode TEXT, scan_depth TEXT,
            aws_account TEXT, aws_services TEXT,
            status TEXT DEFAULT 'pending', progress INTEGER DEFAULT 0,
            current_step TEXT, started_at TEXT, completed_at TEXT, created_by INTEGER
        );
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER, result_type TEXT, severity TEXT, title TEXT,
            description TEXT, host TEXT, service TEXT, cve_id TEXT,
            cvss_score REAL, framework TEXT, control_id TEXT,
            status TEXT DEFAULT 'open', created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS compliance_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework TEXT, control_id TEXT, title TEXT, description TEXT,
            check_type TEXT, check_params TEXT, severity TEXT DEFAULT 'medium',
            enabled INTEGER DEFAULT 1, created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER, severity TEXT, title TEXT, message TEXT,
            channel TEXT, sent INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alert_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE,
            email_enabled INTEGER DEFAULT 0, email_address TEXT,
            slack_enabled INTEGER DEFAULT 0, slack_webhook TEXT,
            alert_on_critical INTEGER DEFAULT 1, alert_on_high INTEGER DEFAULT 1, alert_on_medium INTEGER DEFAULT 0
        );
        """)
        if not db.execute("SELECT 1 FROM users").fetchone():
            for u,e,r in [('admin','admin@esas.local','admin'),
                          ('auditor','auditor@esas.local','auditor'),
                          ('viewer','viewer@esas.local','viewer')]:
                pw = {'admin':'Admin@123','auditor':'Audit@123','viewer':'View@123'}[u]
                db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",
                           (u,e,generate_password_hash(pw),r))
            for ctrl_id,title,desc,ctype in ISO_CHECKS:
                db.execute("INSERT INTO compliance_rules(framework,control_id,title,description,check_type,check_params,severity,created_by) VALUES(?,?,?,?,?,?,?,?)",
                           ('ISO27001',ctrl_id,title,desc,ctype,'{}','high',1))
            for ctrl_id,title,desc,ctype in NIST_CHECKS:
                db.execute("INSERT INTO compliance_rules(framework,control_id,title,description,check_type,check_params,severity,created_by) VALUES(?,?,?,?,?,?,?,?)",
                           ('NIST',ctrl_id,title,desc,ctype,'{}','medium',1))
            db.commit()
            print("DB seeded: admin/Admin@123 | auditor/Audit@123 | viewer/View@123")

VULN_LIBRARY = [
    ('CVE-2024-0982','OpenSSL Buffer Overflow RCE','critical',9.8,'OpenSSL','Heap buffer overflow allows unauthenticated remote code execution'),
    ('CVE-2024-3094','XZ Utils Supply Chain Backdoor','critical',10.0,'XZ Utils','Malicious code in liblzma enables SSH authentication bypass'),
    ('CVE-2023-44487','HTTP/2 Rapid Reset DoS','critical',9.3,'HTTP/2 nginx','Stream cancellation loop enables large-scale denial of service'),
    ('CVE-2024-1234','MySQL Default Credentials','critical',9.1,'MySQL 5.7','Default vendor credentials unchanged on database server'),
    ('CVE-2023-38545','libcurl SOCKS5 Heap Overflow','high',7.5,'libcurl','SOCKS5 proxy handshake heap-based buffer overflow'),
    ('CVE-2024-2201','Spectre v2 Mitigation Bypass','high',7.9,'Linux Kernel','Branch history injection bypasses Spectre v2 mitigations'),
    ('CVE-2023-5678','RDP Exposed Without VPN','high',8.2,'RDP 3389','Remote desktop accessible externally without VPN gateway'),
    ('CVE-2024-23897','Jenkins CLI Arbitrary File Read','medium',6.2,'Jenkins CLI','Unauthenticated file read via CLI args parser'),
    ('CVE-2024-0985','PostgreSQL Privilege Escalation','medium',6.4,'PostgreSQL 15','Non-superuser escalation via MERGE command'),
    ('CVE-2023-50782','python-cryptography Timing Attack','medium',5.9,'python-cryptography','Bleichenbacher oracle in RSA-PSK'),
    ('CVE-2023-5341','ImageMagick Memory Leak','low',3.3,'ImageMagick','Coders memory leak leads to denial of service'),
    ('CVE-2024-0232','SQLite NULL Pointer Dereference','low',2.8,'SQLite 3.44','Crafted SELECT triggers NULL pointer dereference'),
]

ISO_CHECKS = [
    ('A.9.1','Access Control Policy','Documented policy reviewed within 12 months','policy'),
    ('A.9.2','User Access Provisioning','Formal access request records for all accounts','policy'),
    ('A.9.3','MFA for Privileged Access','Multi-factor authentication on all admin accounts','config'),
    ('A.10.1','Cryptographic Controls','AES-256 at rest, TLS 1.3 in transit','config'),
    ('A.12.1','Operational Procedures','Runbooks documented for all critical services','policy'),
    ('A.12.3','Backup Procedures','Daily backups with quarterly restore testing','config'),
    ('A.12.6','Vulnerability Management','Patches applied within defined SLA windows','patch'),
    ('A.13.1','Network Security','VLAN segmentation and firewall rules documented','config'),
    ('A.14.2','Secure Development','SAST/DAST integrated in CI/CD pipeline','config'),
    ('A.16.1','Incident Management','IR plan documented and tested annually','policy'),
    ('A.18.1','Legal Requirements','Compliance with applicable data protection laws','policy'),
]

NIST_CHECKS = [
    ('ID.AM-1','Asset Inventory','Physical devices and software inventoried','config'),
    ('ID.RA-1','Vulnerability Identification','Assets assessed for vulnerabilities regularly','patch'),
    ('PR.AC-1','Access Management','Identities and credentials managed for authorized devices','config'),
    ('PR.DS-1','Data at Rest Protection','Data-at-rest encrypted per policy','config'),
    ('DE.CM-1','Continuous Monitoring','Network monitored for cybersecurity events','config'),
    ('DE.AE-2','Anomaly Analysis','Detected events analysed to understand attack targets','policy'),
    ('RS.RP-1','Response Planning','IR plan executed during or after an incident','policy'),
    ('RC.RP-1','Recovery Planning','Recovery plan executed after a cyber incident','policy'),
]

def simulate_scan(job_id):
    steps = [(5,'Initializing...'),(12,'Discovering hosts...'),(22,'Port scanning...'),
             (35,'Querying CVE database...'),(48,'Scanning vulnerabilities...'),
             (58,'Validating compliance...'),(68,'ISO 27001 checks...'),
             (76,'NIST CSF checks...'),(84,'Log analysis...'),(91,'Risk scoring...'),
             (97,'Generating report...'),(100,'Complete')]
    def run():
        db = get_db()
        db.execute("UPDATE scan_jobs SET status='running',started_at=? WHERE id=?",
                   (datetime.utcnow().isoformat(),job_id)); db.commit()
        job = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        for pct,step in steps:
            time.sleep(random.uniform(0.6,1.2))
            db.execute("UPDATE scan_jobs SET progress=?,current_step=? WHERE id=?",(pct,step,job_id)); db.commit()
        hosts = [f'192.168.1.{random.randint(1,60)}' for _ in range(6)]
        depth = job['scan_depth'] or 'standard'
        num = {'quick':4,'standard':8,'full':len(VULN_LIBRARY)}.get(depth,8)
        for cve,title,sev,cvss,service,desc in random.sample(VULN_LIBRARY,min(num,len(VULN_LIBRARY))):
            db.execute("INSERT INTO scan_results(job_id,result_type,severity,title,description,host,service,cve_id,cvss_score,status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (job_id,'vulnerability',sev,title,desc,random.choice(hosts),service,cve,cvss,'open'))
        if (job['audit_type'] or 'combined') in ('compliance','combined'):
            checks = ISO_CHECKS if depth!='quick' else ISO_CHECKS[:5]
            for ctrl_id,title,desc,_ in checks:
                passed = random.random()>0.35
                db.execute("INSERT INTO scan_results(job_id,result_type,framework,control_id,title,description,severity,status) VALUES(?,?,?,?,?,?,?,?)",
                           (job_id,'compliance','ISO27001',ctrl_id,title,desc,'info' if passed else 'high','pass' if passed else 'fail'))
            for ctrl_id,title,desc,_ in NIST_CHECKS:
                passed = random.random()>0.3
                db.execute("INSERT INTO scan_results(job_id,result_type,framework,control_id,title,description,severity,status) VALUES(?,?,?,?,?,?,?,?)",
                           (job_id,'compliance','NIST',ctrl_id,title,desc,'info' if passed else 'medium','pass' if passed else 'fail'))
        db.execute("UPDATE scan_jobs SET status='completed',completed_at=? WHERE id=?",
                   (datetime.utcnow().isoformat(),job_id))
        for c in db.execute("SELECT * FROM scan_results WHERE job_id=? AND severity='critical' LIMIT 3",(job_id,)).fetchall():
            db.execute("INSERT INTO alerts(job_id,severity,title,message,channel) VALUES(?,?,?,?,?)",
                       (job_id,'critical',f"Critical: {c['title']}",c['description'],'email'))
        db.commit(); db.close()
    threading.Thread(target=run,daemon=True).start()

def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('user_id'): return redirect(url_for('login'))
        return f(*a,**k)
    return w

def api_auth(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('user_id'): return jsonify({'error':'Unauthenticated'}),401
        return f(*a,**k)
    return w

@app.context_processor
def inject_user():
    class U:
        is_authenticated=bool(session.get('user_id'))
        username=session.get('username','')
        role=session.get('role','viewer')
        id=session.get('user_id')
    return {'current_user':U()}

@app.route('/')
def index(): return redirect(url_for('dashboard') if session.get('user_id') else url_for('login'))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        d=request.get_json() or request.form
        with get_db() as db:
            u=db.execute("SELECT * FROM users WHERE username=?",(d.get('username'),)).fetchone()
        if u and check_password_hash(u['password_hash'],d.get('password','')):
            session.update({'user_id':u['id'],'username':u['username'],'role':u['role']})
            with get_db() as db: db.execute("UPDATE users SET last_login=? WHERE id=?",(datetime.utcnow().isoformat(),u['id']))
            return jsonify({'ok':True,'role':u['role']})
        return jsonify({'ok':False,'error':'Invalid credentials'}),401
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html',username=session.get('username'),role=session.get('role'))

@app.route('/configure')
@login_required
def configure(): return render_template('configure.html',username=session.get('username'),role=session.get('role'))

@app.route('/reports')
@login_required
def reports(): return render_template('reports.html',username=session.get('username'),role=session.get('role'))

@app.route('/settings')
@login_required
def settings(): return render_template('settings.html',username=session.get('username'),role=session.get('role'))

@app.route('/api/scan/start',methods=['POST'])
@api_auth
def start_scan():
    if session.get('role') not in ('admin','auditor'): return jsonify({'error':'Permission denied'}),403
    d=request.get_json()
    with get_db() as db:
        cur=db.execute("INSERT INTO scan_jobs(name,audit_type,target_type,target,ports,scan_mode,scan_depth,aws_account,aws_services,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (d.get('name',f"Scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"),d.get('audit_type','combined'),
             d.get('target_type','network'),d.get('target',''),d.get('ports','80,443,22'),
             d.get('scan_mode','manual'),d.get('scan_depth','standard'),d.get('aws_account',''),
             json.dumps(d.get('aws_services',[])),session['user_id']))
        jid=cur.lastrowid
    simulate_scan(jid)
    return jsonify({'ok':True,'job_id':jid})

@app.route('/api/scan/<int:jid>/status')
@api_auth
def scan_status(jid):
    with get_db() as db: j=db.execute("SELECT * FROM scan_jobs WHERE id=?",(jid,)).fetchone()
    if not j: return jsonify({'error':'Not found'}),404
    return jsonify({'id':j['id'],'status':j['status'],'progress':j['progress'],'step':j['current_step'],'started':j['started_at'],'completed':j['completed_at']})

@app.route('/api/scan/<int:jid>/results')
@api_auth
def scan_results(jid):
    with get_db() as db:
        j=db.execute("SELECT * FROM scan_jobs WHERE id=?",(jid,)).fetchone()
        rs=db.execute("SELECT * FROM scan_results WHERE job_id=?",(jid,)).fetchall()
    if not j: return jsonify({'error':'Not found'}),404
    so={'critical':0,'high':1,'medium':2,'low':3,'info':4}
    vulns=sorted([r for r in rs if r['result_type']=='vulnerability'],key=lambda r:so.get(r['severity'],5))
    comp=[r for r in rs if r['result_type']=='compliance']
    scores={}
    for fw in ('ISO27001','NIST'):
        fc=[r for r in comp if r['framework']==fw]
        if fc: scores[fw]=round(sum(1 for r in fc if r['status']=='pass')/len(fc)*100)
    sc={'critical':0,'high':0,'medium':0,'low':0}
    for v in vulns: sc[v['severity']]=sc.get(v['severity'],0)+1
    risk=max(0,100-min(100,sc['critical']*15+sc['high']*7+sc['medium']*3+sc['low']))
    return jsonify({'job':{'id':j['id'],'name':j['name'],'status':j['status'],'audit_type':j['audit_type'],'target':j['target'],'completed':j['completed_at']},
        'risk_score':risk,'sev_counts':sc,'compliance_scores':scores,
        'vulnerabilities':[{'id':r['id'],'cve':r['cve_id'],'title':r['title'],'severity':r['severity'],'cvss':r['cvss_score'],'host':r['host'],'service':r['service'],'description':r['description'],'status':r['status']} for r in vulns],
        'compliance':[{'id':r['id'],'framework':r['framework'],'control_id':r['control_id'],'title':r['title'],'description':r['description'],'status':r['status'],'severity':r['severity']} for r in comp]})

@app.route('/api/scans')
@api_auth
def list_scans():
    with get_db() as db: jobs=db.execute("SELECT * FROM scan_jobs WHERE created_by=? ORDER BY id DESC LIMIT 20",(session['user_id'],)).fetchall()
    return jsonify([{'id':j['id'],'name':j['name'],'status':j['status'],'audit_type':j['audit_type'],'target':j['target'],'created':j['started_at'],'progress':j['progress']} for j in jobs])

@app.route('/api/dashboard/stats')
@api_auth
def dashboard_stats():
    with get_db() as db:
        recent=db.execute("SELECT * FROM scan_jobs WHERE created_by=? AND status='completed' ORDER BY id DESC LIMIT 1",(session['user_id'],)).fetchone()
        if not recent: return jsonify({'no_scans':True})
        rs=db.execute("SELECT * FROM scan_results WHERE job_id=?",(recent['id'],)).fetchall()
        all_jobs=db.execute("SELECT * FROM scan_jobs WHERE created_by=? ORDER BY id DESC LIMIT 7",(session['user_id'],)).fetchall()
        alerts_rows=db.execute("SELECT * FROM alerts WHERE job_id=? ORDER BY id DESC LIMIT 5",(recent['id'],)).fetchall()
    vulns=[r for r in rs if r['result_type']=='vulnerability']
    comp=[r for r in rs if r['result_type']=='compliance']
    sc={'critical':0,'high':0,'medium':0,'low':0}
    for v in vulns: sc[v['severity']]=sc.get(v['severity'],0)+1
    risk=max(0,100-min(100,sc['critical']*15+sc['high']*7+sc['medium']*3+sc['low']))
    scores={}
    for fw in ('ISO27001','NIST'):
        fc=[r for r in comp if r['framework']==fw]
        if fc: scores[fw]=round(sum(1 for r in fc if r['status']=='pass')/len(fc)*100)
    trend=[]
    for j in reversed(list(all_jobs)):
        with get_db() as db2: cnt=db2.execute("SELECT COUNT(*) FROM scan_results WHERE job_id=? AND result_type='vulnerability'",(j['id'],)).fetchone()[0]
        trend.append({'date':j['started_at'][:10] if j['started_at'] else '','count':cnt})
    return jsonify({'risk_score':risk,'sev_counts':sc,'total_vulns':len(vulns),'compliance_scores':scores,'trend':trend,
        'last_scan':recent['completed_at'][:16] if recent['completed_at'] else '',
        'alerts':[{'severity':a['severity'],'title':a['title'],'message':a['message']} for a in alerts_rows]})

@app.route('/api/rules',methods=['GET'])
@api_auth
def get_rules():
    with get_db() as db: rules=db.execute("SELECT * FROM compliance_rules ORDER BY framework,control_id").fetchall()
    return jsonify([{'id':r['id'],'framework':r['framework'],'control_id':r['control_id'],'title':r['title'],'description':r['description'],'check_type':r['check_type'],'check_params':r['check_params'],'severity':r['severity'],'enabled':bool(r['enabled'])} for r in rules])

@app.route('/api/rules',methods=['POST'])
@api_auth
def create_rule():
    if session.get('role') not in ('admin','auditor'): return jsonify({'error':'Unauthorized'}),403
    d=request.get_json()
    with get_db() as db:
        cur=db.execute("INSERT INTO compliance_rules(framework,control_id,title,description,check_type,check_params,severity,created_by) VALUES(?,?,?,?,?,?,?,?)",
            (d['framework'],d['control_id'],d['title'],d.get('description',''),d.get('check_type','policy'),json.dumps(d.get('check_params',{})),d.get('severity','medium'),session['user_id']))
    return jsonify({'ok':True,'id':cur.lastrowid})

@app.route('/api/rules/<int:rid>',methods=['PUT'])
@api_auth
def update_rule(rid):
    if session.get('role') not in ('admin','auditor'): return jsonify({'error':'Unauthorized'}),403
    d=request.get_json()
    fields={k:v for k,v in d.items() if k in ('title','description','check_type','severity','enabled')}
    if 'check_params' in d: fields['check_params']=json.dumps(d['check_params'])
    if fields:
        with get_db() as db: db.execute(f"UPDATE compliance_rules SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?",list(fields.values())+[rid])
    return jsonify({'ok':True})

@app.route('/api/rules/<int:rid>',methods=['DELETE'])
@api_auth
def delete_rule(rid):
    if session.get('role')!='admin': return jsonify({'error':'Unauthorized'}),403
    with get_db() as db: db.execute("DELETE FROM compliance_rules WHERE id=?",(rid,))
    return jsonify({'ok':True})

@app.route('/api/users',methods=['GET'])
@api_auth
def get_users():
    if session.get('role')!='admin': return jsonify({'error':'Unauthorized'}),403
    with get_db() as db: users=db.execute("SELECT id,username,email,role,last_login FROM users").fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/users',methods=['POST'])
@api_auth
def create_user():
    if session.get('role')!='admin': return jsonify({'error':'Unauthorized'}),403
    d=request.get_json()
    try:
        with get_db() as db: db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",(d['username'],d['email'],generate_password_hash(d['password']),d.get('role','viewer')))
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),400

@app.route('/api/users/<int:uid>/role',methods=['PUT'])
@api_auth
def update_role(uid):
    if session.get('role')!='admin': return jsonify({'error':'Unauthorized'}),403
    with get_db() as db: db.execute("UPDATE users SET role=? WHERE id=?",(request.get_json()['role'],uid))
    return jsonify({'ok':True})

@app.route('/api/alert-config',methods=['GET','POST'])
@api_auth
def alert_config():
    uid=session['user_id']
    if request.method=='POST':
        d=request.get_json()
        with get_db() as db:
            ex=db.execute("SELECT id FROM alert_configs WHERE user_id=?",(uid,)).fetchone()
            if ex: db.execute("UPDATE alert_configs SET email_enabled=?,email_address=?,slack_enabled=?,slack_webhook=?,alert_on_critical=?,alert_on_high=?,alert_on_medium=? WHERE user_id=?",
                               (d.get('email_enabled',0),d.get('email_address',''),d.get('slack_enabled',0),d.get('slack_webhook',''),d.get('alert_on_critical',1),d.get('alert_on_high',1),d.get('alert_on_medium',0),uid))
            else: db.execute("INSERT INTO alert_configs(user_id,email_enabled,email_address,slack_enabled,slack_webhook,alert_on_critical,alert_on_high,alert_on_medium) VALUES(?,?,?,?,?,?,?,?)",
                              (uid,d.get('email_enabled',0),d.get('email_address',''),d.get('slack_enabled',0),d.get('slack_webhook',''),d.get('alert_on_critical',1),d.get('alert_on_high',1),d.get('alert_on_medium',0)))
        return jsonify({'ok':True})
    with get_db() as db: cfg=db.execute("SELECT * FROM alert_configs WHERE user_id=?",(uid,)).fetchone()
    return jsonify(dict(cfg) if cfg else {})

@app.route('/api/topology')
@api_auth
def topology():
    return jsonify({'nodes':[
        {'id':'fw','label':'Firewall','type':'firewall','ip':'10.0.0.1','status':'secure'},
        {'id':'sw1','label':'Core Switch','type':'switch','ip':'10.0.0.2','status':'secure'},
        {'id':'sw2','label':'Access Switch','type':'switch','ip':'10.0.0.3','status':'secure'},
        {'id':'app1','label':'APP-SRV-01','type':'server','ip':'192.168.1.10','status':'vulnerable'},
        {'id':'app2','label':'APP-SRV-02','type':'server','ip':'192.168.1.11','status':'secure'},
        {'id':'db1','label':'DB-SRV-04','type':'database','ip':'192.168.1.44','status':'critical'},
        {'id':'ci1','label':'CI-SERVER','type':'server','ip':'192.168.1.60','status':'warning'},
        {'id':'ws1','label':'WS-112','type':'workstation','ip':'192.168.1.112','status':'warning'},
        {'id':'cloud','label':'AWS Cloud','type':'cloud','ip':'N/A','status':'secure'},
    ],'edges':[
        {'from':'fw','to':'sw1'},{'from':'sw1','to':'sw2'},{'from':'sw1','to':'app1'},
        {'from':'sw1','to':'app2'},{'from':'sw1','to':'db1'},{'from':'sw2','to':'ci1'},
        {'from':'sw2','to':'ws1'},{'from':'fw','to':'cloud'},
    ]})

@app.route('/api/report/<int:jid>/pdf')
@api_auth
def export_pdf(jid):
    with get_db() as db:
        j=db.execute("SELECT * FROM scan_jobs WHERE id=?",(jid,)).fetchone()
        rs=db.execute("SELECT * FROM scan_results WHERE job_id=?",(jid,)).fetchall()
    vulns=[r for r in rs if r['result_type']=='vulnerability']
    comp=[r for r in rs if r['result_type']=='compliance']
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,HRFlowable
        from reportlab.lib.enums import TA_CENTER
        buf=io.BytesIO()
        doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=2*cm,rightMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm)
        styles=getSampleStyleSheet(); story=[]
        ts=ParagraphStyle('t',fontSize=20,fontName='Helvetica-Bold',spaceAfter=6,alignment=TA_CENTER)
        h2=ParagraphStyle('h',fontSize=13,fontName='Helvetica-Bold',spaceAfter=4,textColor=colors.HexColor('#1a3a5c'))
        story.append(Paragraph('FalconX — Enterprise Security Audit Report',ts))
        story.append(Paragraph(f"Scan: {j['name']} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",styles['Normal']))
        story.append(Spacer(1,0.4*cm)); story.append(HRFlowable(width='100%',thickness=1,color=colors.HexColor('#1a3a5c'))); story.append(Spacer(1,0.3*cm))
        sc={'critical':0,'high':0,'medium':0,'low':0}
        for v in vulns: sc[v['severity']]=sc.get(v['severity'],0)+1
        risk=max(0,100-min(100,sc['critical']*15+sc['high']*7+sc['medium']*3+sc['low']))
        story.append(Paragraph('Executive Summary',h2))
        sd=[['Metric','Value'],['Risk Score',f"{risk}/100"],['Total Vulnerabilities',str(len(vulns))],
            ['Critical',str(sc['critical'])],['High',str(sc['high'])],['Medium',str(sc['medium'])],['Low',str(sc['low'])],
            ['Audit Type',str(j['audit_type']).title()],['Target',str(j['target'] or 'N/A')]]
        t=Table(sd,colWidths=[8*cm,8*cm])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a3a5c')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#f0f4f8'),colors.white]),
            ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#cccccc')),('FONTSIZE',(0,0),(-1,-1),10),('PADDING',(0,0),(-1,-1),6)]))
        story.append(t); story.append(Spacer(1,0.4*cm))
        if vulns:
            story.append(Paragraph('Vulnerability Findings',h2))
            vd=[['CVE ID','Severity','CVSS','Host','Service']]
            sc_colors={'critical':colors.HexColor('#fee2e2'),'high':colors.HexColor('#fef3c7'),'medium':colors.HexColor('#dbeafe'),'low':colors.HexColor('#d1fae5')}
            for v in sorted(vulns,key=lambda x:{'critical':0,'high':1,'medium':2,'low':3}.get(x['severity'],4)):
                vd.append([v['cve_id'] or 'N/A',v['severity'].upper(),str(v['cvss_score'] or ''),v['host'] or '',v['service'] or ''])
            vt=Table(vd,colWidths=[3.5*cm,2.5*cm,2*cm,4*cm,4*cm])
            vts=[('BACKGROUND',(0,0),(-1,0),colors.HexColor('#374151')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                 ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#e5e7eb')),
                 ('FONTSIZE',(0,0),(-1,-1),9),('PADDING',(0,0),(-1,-1),5)]
            for i,row in enumerate(vd[1:],1):
                vts.append(('BACKGROUND',(0,i),(-1,i),sc_colors.get(row[1].lower(),colors.white)))
            vt.setStyle(TableStyle(vts)); story.append(vt); story.append(Spacer(1,0.4*cm))
        for fw in ('ISO27001','NIST'):
            fc=[r for r in comp if r['framework']==fw]
            if not fc: continue
            passed=sum(1 for r in fc if r['status']=='pass')
            story.append(Paragraph(f"{fw} Compliance — {round(passed/len(fc)*100)}% ({passed}/{len(fc)})",h2))
            cd=[['Control','Title','Result']]+[[c['control_id'],c['title'],'PASS' if c['status']=='pass' else 'FAIL'] for c in fc]
            ct=Table(cd,colWidths=[3*cm,11*cm,3*cm])
            cts=[('BACKGROUND',(0,0),(-1,0),colors.HexColor('#374151')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                 ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#e5e7eb')),
                 ('FONTSIZE',(0,0),(-1,-1),8),('PADDING',(0,0),(-1,-1),4)]
            for i,row in enumerate(cd[1:],1):
                cts.append(('BACKGROUND',(2,i),(2,i),colors.HexColor('#d1fae5') if row[2]=='PASS' else colors.HexColor('#fee2e2')))
            ct.setStyle(TableStyle(cts)); story.append(ct); story.append(Spacer(1,0.3*cm))
        doc.build(story); buf.seek(0)
        return send_file(buf,mimetype='application/pdf',download_name=f"ESAS_{j['name'].replace(' ','_')}.pdf",as_attachment=True)
    except ImportError:
        lines=[f"ENTERPRISE SECURITY AUDIT REPORT\nScan: {j['name']}\nGenerated: {datetime.utcnow().isoformat()}\n\nVULNERABILITIES\n"+"-"*60]
        for v in vulns: lines.append(f"[{v['severity'].upper()}] {v['cve_id']} - {v['title']} ({v['host']})")
        lines.append("\nCOMPLIANCE\n"+"-"*60)
        for r in comp: lines.append(f"[{r['status'].upper()}] {r['framework']} {r['control_id']} - {r['title']}")
        return send_file(io.BytesIO('\n'.join(lines).encode()),mimetype='text/plain',download_name=f'ESAS_Report_{jid}.txt',as_attachment=True)

if __name__=='__main__':
    init_db()
    print("\n🔐 FalconX ESAS ready at http://localhost:5000")
    print("   admin/Admin@123 | auditor/Audit@123 | viewer/View@123\n")
    app.run(debug=True,port=5000)

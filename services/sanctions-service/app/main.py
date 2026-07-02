from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
from urllib.parse import urlparse
import os
import traceback
from datetime import datetime, timedelta
import uuid
import numpy as np
from sklearn.ensemble import IsolationForest

app = FastAPI(title="Hisn Risk Intelligence Platform", version="4.0.0")

# ============================================================
# نماذج AML
# ============================================================
HIGH_RISK_COUNTRIES = {"IR", "KP", "SY", "AF", "MM"}

amounts_model = IsolationForest(contamination=0.1, random_state=42)
X_train = np.random.normal(50000, 20000, 1000).reshape(-1, 1)
amounts_model.fit(X_train)

class AMLRequest(BaseModel):
    customer_id: str
    amount: float
    currency: str = "SAR"
    country: str
    transaction_type: str
    timestamp: Optional[str] = None

class AMLRiskAssessment(BaseModel):
    risk_score: float
    risk_level: str
    triggered_rules: List[str] = []

# ============================================================
# نماذج كشف الاحتيال
# ============================================================
class FraudRequest(BaseModel):
    customer_id: str
    amount: float
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    transaction_type: str = "payment"
    failed_attempts: int = 0
    timestamp: Optional[str] = None

class FraudAssessment(BaseModel):
    fraud_score: float
    fraud_level: str
    triggered_rules: List[str] = []

# ============================================================
# نماذج العقوبات
# ============================================================
class SanctionCheckRequest(BaseModel):
    full_name: str
    language: str = "ar"

class MatchResult(BaseModel):
    matched_name: str
    list_type: str
    score: float

class SanctionCheckResponse(BaseModel):
    is_match: bool
    matches: List[MatchResult] = []

# ============================================================
# نماذج SAR (تقارير الاشتباه)
# ============================================================
class SARRequest(BaseModel):
    subject_name: str
    subject_id: Optional[str] = None
    transaction_id: Optional[str] = None
    reason: str
    triggered_rules: List[str] = []
    risk_score: float
    reported_by: str = "system"
    notes: Optional[str] = None

class SARResponse(BaseModel):
    sar_id: str
    status: str
    created_at: str

# ============================================================
# نماذج إدارة الحالات (Case Management)
# ============================================================
class CaseCreateRequest(BaseModel):
    alert_id: Optional[str] = None
    case_type: str  # "sanctions", "aml", "fraud"
    subject_name: str
    subject_id: Optional[str] = None
    priority: str = "medium"  # "low", "medium", "high", "critical"
    description: str
    assigned_to: Optional[str] = None
    source: str = "system"

class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None  # "open", "in_progress", "escalated", "closed"
    notes: Optional[str] = None
    resolution: Optional[str] = None
    assigned_to: Optional[str] = None

class CaseResponse(BaseModel):
    case_id: str
    status: str
    created_at: str

# ============================================================
# دوال قاعدة البيانات
# ============================================================
def get_db():
    db_url = os.getenv("DATABASE_URL")
    if db_url is None:
        raise HTTPException(status_code=500, detail="DATABASE_URL not set")
    result = urlparse(db_url)
    return psycopg2.connect(
        database=result.path[1:],
        user=result.username,
        password=result.password,
        host=result.hostname,
        port=result.port
    )

def init_db():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE SCHEMA IF NOT EXISTS hisn;
            CREATE TABLE IF NOT EXISTS hisn.tenants (
                id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                api_key VARCHAR(64) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.watchlist (
                id SERIAL PRIMARY KEY,
                full_name_ar VARCHAR(500),
                full_name_en VARCHAR(500),
                list_type VARCHAR(50),
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.aml_transactions (
                id SERIAL PRIMARY KEY,
                customer_id VARCHAR(255),
                amount DECIMAL(15,2),
                currency VARCHAR(10),
                country VARCHAR(5),
                transaction_type VARCHAR(50),
                timestamp TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.fraud_transactions (
                id SERIAL PRIMARY KEY,
                customer_id VARCHAR(255),
                amount DECIMAL(15,2),
                device_id VARCHAR(255),
                ip_address VARCHAR(50),
                location VARCHAR(255),
                transaction_type VARCHAR(50),
                failed_attempts INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.customer_profiles (
                customer_id VARCHAR(255) PRIMARY KEY,
                avg_amount DECIMAL(15,2) DEFAULT 0,
                common_location VARCHAR(255),
                common_device VARCHAR(255),
                total_transactions INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS hisn.sar_reports (
                id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                sar_id VARCHAR(50) UNIQUE NOT NULL,
                subject_name VARCHAR(500),
                subject_id VARCHAR(255),
                transaction_id VARCHAR(255),
                reason TEXT,
                triggered_rules TEXT,
                risk_score DECIMAL(5,2),
                reported_by VARCHAR(255),
                notes TEXT,
                status VARCHAR(50) DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.cases (
                id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                case_id VARCHAR(50) UNIQUE NOT NULL,
                alert_id VARCHAR(255),
                case_type VARCHAR(50),
                subject_name VARCHAR(500),
                subject_id VARCHAR(255),
                priority VARCHAR(50) DEFAULT 'medium',
                status VARCHAR(50) DEFAULT 'open',
                description TEXT,
                assigned_to VARCHAR(255),
                resolution TEXT,
                source VARCHAR(100) DEFAULT 'system',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.case_notes (
                id SERIAL PRIMARY KEY,
                case_id VARCHAR(50),
                note TEXT,
                created_by VARCHAR(255) DEFAULT 'system',
                created_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()

        cur.execute("SELECT COUNT(*) FROM hisn.watchlist")
        if cur.fetchone()[0] == 0:
            cur.execute("""
                INSERT INTO hisn.watchlist (full_name_ar, full_name_en, list_type) VALUES
                ('أسامة بن لادن', 'Osama bin Laden', 'UN'),
                ('أيمن الظواهري', 'Ayman al-Zawahiri', 'UN'),
                ('أبو بكر البغدادي', 'Abu Bakr al-Baghdadi', 'UN'),
                ('قاسم الريمي', 'Qasim al-Raymi', 'UN')
            """)
            conn.commit()

        cur.close()
        conn.close()
        print("✅ Database ready")
    except Exception as e:
        print(f"❌ DB init error: {e}")
        traceback.print_exc()

@app.on_event("startup")
async def startup():
    init_db()

# ============================================================
# نقطة نهاية فحص العقوبات
# ============================================================
@app.post("/sanctions/check", response_model=SanctionCheckResponse)
async def check_sanctions(request: SanctionCheckRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        lang = request.language
        cur.execute(
            f"SELECT full_name_ar, full_name_en, list_type FROM hisn.watchlist WHERE full_name_{'ar' if lang == 'ar' else 'en'} ILIKE %s",
            (f"%{request.full_name}%",)
        )
        results = cur.fetchall()
        cur.close()
        conn.close()
        matches = [MatchResult(matched_name=r[1] or r[0], list_type=r[2], score=1.0) for r in results]
        return SanctionCheckResponse(is_match=len(matches) > 0, matches=matches)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# نقطة نهاية AML
# ============================================================
@app.post("/aml/evaluate", response_model=AMLRiskAssessment)
async def evaluate_aml(request: AMLRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        risk_score = 0.0
        triggered = []

        if request.amount > 50000:
            triggered.append("high_amount_exceeds_50k")
            risk_score += 0.4

        if request.country.upper() in HIGH_RISK_COUNTRIES:
            triggered.append("high_risk_country")
            risk_score += 0.5

        ref_time = datetime.fromisoformat(request.timestamp) if request.timestamp else datetime.utcnow()
        window_start = ref_time - timedelta(minutes=10)
        cur.execute(
            "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = %s AND timestamp >= %s",
            (request.customer_id, window_start)
        )
        if cur.fetchone()[0] >= 5:
            triggered.append("rapid_transactions_5_in_10min")
            risk_score += 0.3

        if request.transaction_type == "deposit" and 40000 <= request.amount < 50000:
            day_start = ref_time - timedelta(hours=24)
            cur.execute(
                "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = %s AND transaction_type='deposit' AND amount >= 40000 AND amount < 50000 AND timestamp >= %s",
                (request.customer_id, day_start)
            )
            if cur.fetchone()[0] >= 3:
                triggered.append("possible_structuring")
                risk_score += 0.6

        amount_np = np.array([[request.amount]])
        if amounts_model.predict(amount_np)[0] == -1:
            triggered.append("ml_anomaly_amount")
            risk_score += 0.3

        cur.execute(
            "INSERT INTO hisn.aml_transactions (customer_id, amount, currency, country, transaction_type, timestamp) VALUES (%s,%s,%s,%s,%s,%s)",
            (request.customer_id, request.amount, request.currency, request.country.upper(), request.transaction_type, ref_time)
        )
        conn.commit()
        cur.close()
        conn.close()

        risk_score = min(risk_score, 1.0)
        risk_level = "high" if risk_score >= 0.7 else "medium" if risk_score >= 0.4 else "low"
        return AMLRiskAssessment(risk_score=round(risk_score, 2), risk_level=risk_level, triggered_rules=triggered)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# نقطة نهاية كشف الاحتيال
# ============================================================
@app.post("/fraud/check", response_model=FraudAssessment)
async def check_fraud(request: FraudRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        fraud_score = 0.0
        triggered = []

        ref_time = datetime.fromisoformat(request.timestamp) if request.timestamp else datetime.utcnow()
        window_start = ref_time - timedelta(minutes=5)
        cur.execute(
            "SELECT COUNT(*) FROM hisn.fraud_transactions WHERE customer_id = %s AND timestamp >= %s",
            (request.customer_id, window_start)
        )
        if cur.fetchone()[0] >= 3:
            triggered.append("high_velocity_3_in_5min")
            fraud_score += 0.5

        cur.execute("SELECT AVG(amount) FROM hisn.fraud_transactions WHERE customer_id = %s", (request.customer_id,))
        avg = cur.fetchone()[0]
        if avg and request.amount > avg * 3:
            triggered.append("unusual_amount_3x_avg")
            fraud_score += 0.4

        if request.location:
            cur.execute("SELECT common_location FROM hisn.customer_profiles WHERE customer_id = %s", (request.customer_id,))
            profile = cur.fetchone()
            if profile and profile[0] and profile[0] != request.location:
                triggered.append("location_mismatch")
                fraud_score += 0.6

        hour = ref_time.hour
        if 0 <= hour < 5:
            triggered.append("off_hours_transaction")
            fraud_score += 0.2

        if request.failed_attempts >= 3:
            triggered.append("multiple_failed_attempts")
            fraud_score += 0.7

        cur.execute(
            "INSERT INTO hisn.fraud_transactions (customer_id, amount, device_id, ip_address, location, transaction_type, failed_attempts, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (request.customer_id, request.amount, request.device_id, request.ip_address, request.location, request.transaction_type, request.failed_attempts, ref_time)
        )
        cur.execute(
            """
            INSERT INTO hisn.customer_profiles (customer_id, avg_amount, common_location, common_device, total_transactions)
            VALUES (%s, %s, %s, %s, 1)
            ON CONFLICT (customer_id) DO UPDATE SET
                avg_amount = (hisn.customer_profiles.avg_amount * hisn.customer_profiles.total_transactions + %s) / (hisn.customer_profiles.total_transactions + 1),
                common_location = COALESCE(%s, hisn.customer_profiles.common_location),
                common_device = COALESCE(%s, hisn.customer_profiles.common_device),
                total_transactions = hisn.customer_profiles.total_transactions + 1
            """,
            (request.customer_id, request.amount, request.location, request.device_id, request.amount, request.location, request.device_id)
        )
        conn.commit()
        cur.close()
        conn.close()

        fraud_score = min(fraud_score, 1.0)
        fraud_level = "high" if fraud_score >= 0.7 else "medium" if fraud_score >= 0.4 else "low"
        return FraudAssessment(fraud_score=round(fraud_score, 2), fraud_level=fraud_level, triggered_rules=triggered)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# نقطة نهاية SAR (تقارير الاشتباه)
# ============================================================
@app.post("/sar/generate", response_model=SARResponse)
async def generate_sar(request: SARRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        sar_id = f"SAR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        cur.execute(
            """
            INSERT INTO hisn.sar_reports (sar_id, subject_name, subject_id, transaction_id, reason, triggered_rules, risk_score, reported_by, notes, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'submitted')
            """,
            (sar_id, request.subject_name, request.subject_id, request.transaction_id, request.reason, ",".join(request.triggered_rules), request.risk_score, request.reported_by, request.notes)
        )
        conn.commit()
        cur.close()
        conn.close()
        return SARResponse(sar_id=sar_id, status="submitted", created_at=datetime.utcnow().isoformat())
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sar/list")
async def list_sars(limit: int = Query(20), status: Optional[str] = None):
    try:
        conn = get_db()
        cur = conn.cursor()
        if status:
            cur.execute("SELECT sar_id, subject_name, risk_score, status, created_at FROM hisn.sar_reports WHERE status = %s ORDER BY created_at DESC LIMIT %s", (status, limit))
        else:
            cur.execute("SELECT sar_id, subject_name, risk_score, status, created_at FROM hisn.sar_reports ORDER BY created_at DESC LIMIT %s", (limit,))
        results = cur.fetchall()
        cur.close()
        conn.close()
        return [{"sar_id": r[0], "subject_name": r[1], "risk_score": float(r[2]), "status": r[3], "created_at": r[4].isoformat()} for r in results]
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# نقطة نهاية إدارة الحالات (Case Management)
# ============================================================
@app.post("/cases/create", response_model=CaseResponse)
async def create_case(request: CaseCreateRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        cur.execute(
            """
            INSERT INTO hisn.cases (case_id, alert_id, case_type, subject_name, subject_id, priority, status, description, assigned_to, source)
            VALUES (%s, %s, %s, %s, %s, %s, 'open', %s, %s, %s)
            """,
            (case_id, request.alert_id, request.case_type, request.subject_name, request.subject_id, request.priority, request.description, request.assigned_to, request.source)
        )
        if request.description:
            cur.execute(
                "INSERT INTO hisn.case_notes (case_id, note, created_by) VALUES (%s, %s, 'system')",
                (case_id, request.description)
            )
        conn.commit()
        cur.close()
        conn.close()
        return CaseResponse(case_id=case_id, status="open", created_at=datetime.utcnow().isoformat())
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/cases/{case_id}/status")
async def update_case_status(case_id: str, request: CaseUpdateRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        updates = []
        values = []
        if request.status:
            updates.append("status = %s")
            values.append(request.status)
        if request.assigned_to:
            updates.append("assigned_to = %s")
            values.append(request.assigned_to)
        if request.resolution:
            updates.append("resolution = %s")
            values.append(request.resolution)
        updates.append("updated_at = NOW()")
        values.append(case_id)
        cur.execute(f"UPDATE hisn.cases SET {', '.join(updates)} WHERE case_id = %s", values)
        if request.notes:
            cur.execute("INSERT INTO hisn.case_notes (case_id, note) VALUES (%s, %s)", (case_id, request.notes))
        conn.commit()
        cur.close()
        conn.close()
        return {"message": "Case updated", "case_id": case_id}
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cases/list")
async def list_cases(limit: int = Query(20), status: Optional[str] = None, case_type: Optional[str] = None):
    try:
        conn = get_db()
        cur = conn.cursor()
        query = "SELECT case_id, case_type, subject_name, priority, status, assigned_to, created_at FROM hisn.cases WHERE 1=1"
        params = []
        if status:
            query += " AND status = %s"
            params.append(status)
        if case_type:
            query += " AND case_type = %s"
            params.append(case_type)
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(query, params)
        results = cur.fetchall()
        cur.close()
        conn.close()
        return [{"case_id": r[0], "case_type": r[1], "subject_name": r[2], "priority": r[3], "status": r[4], "assigned_to": r[5], "created_at": r[6].isoformat()} for r in results]
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cases/{case_id}")
async def get_case(case_id: str):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT case_id, alert_id, case_type, subject_name, subject_id, priority, status, description, assigned_to, resolution, source, created_at, updated_at FROM hisn.cases WHERE case_id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        cur.execute("SELECT note, created_by, created_at FROM hisn.case_notes WHERE case_id = %s ORDER BY created_at", (case_id,))
        notes = [{"note": n[0], "created_by": n[1], "created_at": n[2].isoformat()} for n in cur.fetchall()]
        cur.close()
        conn.close()
        return {
            "case_id": case[0], "alert_id": case[1], "case_type": case[2], "subject_name": case[3],
            "subject_id": case[4], "priority": case[5], "status": case[6], "description": case[7],
            "assigned_to": case[8], "resolution": case[9], "source": case[10],
            "created_at": case[11].isoformat(), "updated_at": case[12].isoformat(), "notes": notes
        }
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# فحص السلامة
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok", "service": "hisn-platform"}

# ============================================================
# لوحة التحكم (محدثة - 5 أقسام)
# ============================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>حِصْن | منصة الامتثال المالي</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Tajawal', sans-serif; background: #0f172a; color: #e2e8f0; display: flex; min-height: 100vh; }
        .sidebar { width: 260px; background: #1e293b; padding: 30px 20px; border-left: 1px solid #334155; overflow-y: auto; }
        .sidebar h2 { color: #f59e0b; margin-bottom: 40px; font-size: 24px; }
        .sidebar button { display: block; width: 100%; padding: 14px; margin-bottom: 12px; background: #334155; color: #e2e8f0; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; transition: 0.3s; text-align: right; }
        .sidebar button.active, .sidebar button:hover { background: #f59e0b; color: #0f172a; font-weight: bold; }
        .main { flex: 1; padding: 40px; overflow-y: auto; }
        .section { display: none; }
        .section.active { display: block; }
        .card { background: #1e293b; padding: 30px; border-radius: 16px; margin-bottom: 20px; border: 1px solid #334155; }
        .card h3 { margin-bottom: 20px; color: #f59e0b; }
        .form-group { margin-bottom: 18px; }
        label { display: block; margin-bottom: 6px; color: #94a3b8; }
        input, select, textarea { width: 100%; padding: 12px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
        textarea { min-height: 100px; resize: vertical; }
        button.submit { padding: 12px 30px; background: #f59e0b; color: #0f172a; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; }
        button.refresh { padding: 8px 20px; background: #334155; color: #e2e8f0; border: 1px solid #475569; border-radius: 8px; cursor: pointer; font-size: 14px; }
        .result { margin-top: 20px; padding: 20px; border-radius: 8px; }
        .result.high { background: #7f1d1d; border: 1px solid #ef4444; }
        .result.medium { background: #78350f; border: 1px solid #f59e0b; }
        .result.low { background: #14532d; border: 1px solid #22c55e; }
        .result.match { background: #7f1d1d; border: 1px solid #ef4444; }
        .result.no-match { background: #14532d; border: 1px solid #22c55e; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 14px; margin: 4px; }
        .badge.rule { background: #f59e0b; color: #0f172a; }
        .badge.high { background: #ef4444; color: white; }
        .badge.medium { background: #f59e0b; color: #0f172a; }
        .badge.low { background: #22c55e; color: white; }
        .badge.open { background: #3b82f6; color: white; }
        .badge.closed { background: #6b7280; color: white; }
        .badge.submitted { background: #8b5cf6; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: right; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; font-weight: bold; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>🛡️ حِصْن v4.0</h2>
        <button class="active" onclick="showSection('sanctions')">🔍 فحص العقوبات</button>
        <button onclick="showSection('aml')">💰 تقييم AML</button>
        <button onclick="showSection('fraud')">🕵️ كشف الاحتيال</button>
        <button onclick="showSection('sar')">📄 تقارير SAR</button>
        <button onclick="showSection('cases')">📋 إدارة الحالات</button>
    </div>
    <div class="main">
        <!-- فحص العقوبات -->
        <div id="section-sanctions" class="section active">
            <div class="card">
                <h3>🔍 فحص قوائم العقوبات</h3>
                <div class="form-group"><label>الاسم الكامل</label><input type="text" id="sanction-name" placeholder="أدخل الاسم للفحص..."></div>
                <div class="form-group"><label>اللغة</label><select id="sanction-lang"><option value="ar">العربية</option><option value="en">الإنجليزية</option></select></div>
                <button class="submit" onclick="checkSanctions()">فحص</button>
                <div id="sanction-result"></div>
            </div>
        </div>

        <!-- AML -->
        <div id="section-aml" class="section">
            <div class="card">
                <h3>💰 تقييم مخاطر غسل الأموال</h3>
                <div class="form-group"><label>رقم العميل</label><input type="text" id="aml-customer" placeholder="Customer ID"></div>
                <div class="form-group"><label>المبلغ (ريال)</label><input type="number" id="aml-amount" placeholder="المبلغ"></div>
                <div class="form-group"><label>الدولة</label><select id="aml-country"><option value="SA">🇸🇦 السعودية</option><option value="IR">🇮🇷 إيران</option><option value="SY">🇸🇾 سوريا</option><option value="AF">🇦🇫 أفغانستان</option><option value="US">🇺🇸 الولايات المتحدة</option></select></div>
                <div class="form-group"><label>نوع المعاملة</label><select id="aml-type"><option value="deposit">إيداع</option><option value="withdrawal">سحب</option><option value="transfer">تحويل</option></select></div>
                <button class="submit" onclick="evaluateAML()">تقييم</button>
                <div id="aml-result"></div>
            </div>
        </div>

        <!-- كشف الاحتيال -->
        <div id="section-fraud" class="section">
            <div class="card">
                <h3>🕵️ كشف الاحتيال</h3>
                <div class="form-group"><label>رقم العميل</label><input type="text" id="fraud-customer" placeholder="Customer ID"></div>
                <div class="form-group"><label>المبلغ (ريال)</label><input type="number" id="fraud-amount" placeholder="المبلغ"></div>
                <div class="form-group"><label>الموقع</label><input type="text" id="fraud-location" placeholder="مثال: الرياض"></div>
                <div class="form-group"><label>نوع المعاملة</label><select id="fraud-type"><option value="payment">دفع</option><option value="transfer">تحويل</option><option value="withdrawal">سحب</option></select></div>
                <div class="form-group"><label>محاولات فاشلة سابقة</label><input type="number" id="fraud-failed" value="0"></div>
                <button class="submit" onclick="checkFraud()">فحص</button>
                <div id="fraud-result"></div>
            </div>
        </div>

        <!-- تقارير SAR -->
        <div id="section-sar" class="section">
            <div class="card">
                <h3>📄 إنشاء تقرير اشتباه (SAR)</h3>
                <div class="form-group"><label>اسم الشخص / الكيان</label><input type="text" id="sar-subject" placeholder="الاسم الكامل"></div>
                <div class="form-group"><label>رقم هوية العميل</label><input type="text" id="sar-subject-id" placeholder="رقم الهوية (اختياري)"></div>
                <div class="form-group"><label>سبب الاشتباه</label><textarea id="sar-reason" placeholder="وصف سبب الاشتباه..."></textarea></div>
                <div class="form-group"><label>القواعد المشغلة</label><input type="text" id="sar-rules" placeholder="مثال: high_amount_exceeds_50k, high_risk_country"></div>
                <div class="form-group"><label>درجة الخطورة</label><input type="number" id="sar-score" placeholder="0.0 - 1.0" step="0.1" min="0" max="1"></div>
                <button class="submit" onclick="generateSAR()">إنشاء التقرير</button>
                <div id="sar-result"></div>
            </div>
            <div class="card">
                <h3>📋 قائمة التقارير</h3>
                <button class="refresh" onclick="loadSARs()">تحديث</button>
                <div id="sar-list"></div>
            </div>
        </div>

        <!-- إدارة الحالات -->
        <div id="section-cases" class="section">
            <div class="card">
                <h3>📝 إنشاء حالة جديدة</h3>
                <div class="form-group"><label>نوع الحالة</label><select id="case-type"><option value="sanctions">عقوبات</option><option value="aml">AML</option><option value="fraud">احتيال</option></select></div>
                <div class="form-group"><label>اسم الشخص / الكيان</label><input type="text" id="case-subject" placeholder="الاسم الكامل"></div>
                <div class="form-group"><label>الأولوية</label><select id="case-priority"><option value="low">منخفضة</option><option value="medium" selected>متوسطة</option><option value="high">عالية</option><option value="critical">حرجة</option></select></div>
                <div class="form-group"><label>الوصف</label><textarea id="case-description" placeholder="وصف الحالة..."></textarea></div>
                <button class="submit" onclick="createCase()">إنشاء الحالة</button>
                <div id="case-create-result"></div>
            </div>
            <div class="card">
                <h3>📋 قائمة الحالات</h3>
                <button class="refresh" onclick="loadCases()">تحديث</button>
                <div id="case-list"></div>
            </div>
        </div>
    </div>

    <script>
        function showSection(section) {
            document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
            document.getElementById('section-' + section).classList.add('active');
            document.querySelectorAll('.sidebar button').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            if (section === 'sar') loadSARs();
            if (section === 'cases') loadCases();
        }

        async function checkSanctions() {
            const name = document.getElementById('sanction-name').value;
            const lang = document.getElementById('sanction-lang').value;
            const resultDiv = document.getElementById('sanction-result');
            resultDiv.innerHTML = '⏳ جاري الفحص...';
            try {
                const res = await fetch('/sanctions/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ full_name: name, language: lang })
                });
                const data = await res.json();
                if (data.is_match) {
                    resultDiv.innerHTML = '<div class="result match"><strong>⚠️ تم العثور على تطابق!</strong><br>' + data.matches.map(m => m.matched_name + ' (' + m.list_type + ')').join('<br>') + '</div>';
                } else {
                    resultDiv.innerHTML = '<div class="result no-match"><strong>✅ لا يوجد تطابق.</strong></div>';
                }
            } catch (e) {
                resultDiv.innerHTML = '<div class="result high">❌ حدث خطأ في الاتصال بالخدمة.</div>';
            }
        }

        async function evaluateAML() {
            const customer = document.getElementById('aml-customer').value;
            const amount = parseFloat(document.getElementById('aml-amount').value);
            const country = document.getElementById('aml-country').value;
            const type = document.getElementById('aml-type').value;
            const resultDiv = document.getElementById('aml-result');
            resultDiv.innerHTML = '⏳ جاري التقييم...';
            try {
                const res = await fetch('/aml/evaluate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ customer_id: customer, amount: amount, currency: 'SAR', country: country, transaction_type: type })
                });
                const data = await res.json();
                const levelClass = data.risk_level === 'high' ? 'high' : data.risk_level === 'medium' ? 'medium' : 'low';
                let html = `<div class="result ${levelClass}"><strong>درجة الخطورة: ${data.risk_score} (${data.risk_level === 'high' ? 'مرتفعة' : data.risk_level === 'medium' ? 'متوسطة' : 'منخفضة'})</strong><br>`;
                if (data.triggered_rules.length > 0) {
                    html += 'القواعد المشغلة: ' + data.triggered_rules.map(r => '<span class="badge rule">' + r + '</span>').join(' ');
                }
                html += '</div>';
                resultDiv.innerHTML = html;
            } catch (e) {
                resultDiv.innerHTML = '<div class="result high">❌ حدث خطأ في الاتصال بالخدمة.</div>';
            }
        }

        async function checkFraud() {
            const customer = document.getElementById('fraud-customer').value;
            const amount = parseFloat(document.getElementById('fraud-amount').value);
            const location = document.getElementById('fraud-location').value;
            const type = document.getElementById('fraud-type').value;
            const failed = parseInt(document.getElementById('fraud-failed').value);
            const resultDiv = document.getElementById('fraud-result');
            resultDiv.innerHTML = '⏳ جاري الفحص...';
            try {
                const res = await fetch('/fraud/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ customer_id: customer, amount: amount, location: location, transaction_type: type, failed_attempts: failed })
                });
                const data = await res.json();
                const levelClass = data.fraud_level === 'high' ? 'high' : data.fraud_level === 'medium' ? 'medium' : 'low';
                let html = `<div class="result ${levelClass}"><strong>درجة الاحتيال: ${data.fraud_score} (${data.fraud_level === 'high' ? 'مرتفعة' : data.fraud_level === 'medium' ? 'متوسطة' : 'منخفضة'})</strong><br>`;
                if (data.triggered_rules.length > 0) {
                    html += 'القواعد المشغلة: ' + data.triggered_rules.map(r => '<span class="badge rule">' + r + '</span>').join(' ');
                }
                html += '</div>';
                resultDiv.innerHTML = html;
            } catch (e) {
                resultDiv.innerHTML = '<div class="result high">❌ حدث خطأ في الاتصال بالخدمة.</div>';
            }
        }

        async function generateSAR() {
            const subject = document.getElementById('sar-subject').value;
            const subjectId = document.getElementById('sar-subject-id').value;
            const reason = document.getElementById('sar-reason').value;
            const rules = document.getElementById('sar-rules').value.split(',').map(r => r.trim()).filter(r => r);
            const score = parseFloat(document.getElementById('sar-score').value) || 0;
            const resultDiv = document.getElementById('sar-result');
            resultDiv.innerHTML = '⏳ جاري إنشاء التقرير...';
            try {
                const res = await fetch('/sar/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subject_name: subject, subject_id: subjectId, reason: reason, triggered_rules: rules, risk_score: score })
                });
                const data = await res.json();
                resultDiv.innerHTML = `<div class="result low"><strong>✅ تم إنشاء التقرير بنجاح!</strong><br>رقم التقرير: <strong>${data.sar_id}</strong><br>الحالة: ${data.status}</div>`;
                loadSARs();
            } catch (e) {
                resultDiv.innerHTML = '<div class="result high">❌ حدث خطأ في الاتصال بالخدمة.</div>';
            }
        }

        async function loadSARs() {
            const listDiv = document.getElementById('sar-list');
            listDiv.innerHTML = '⏳ جاري التحميل...';
            try {
                const res = await fetch('/sar/list?limit=20');
                const data = await res.json();
                if (data.length === 0) {
                    listDiv.innerHTML = '<p>لا توجد تقارير حتى الآن.</p>';
                    return;
                }
                let html = '<table><tr><th>رقم التقرير</th><th>الاسم</th><th>الخطورة</th><th>الحالة</th><th>التاريخ</th></tr>';
                data.forEach(sar => {
                    html += `<tr><td>${sar.sar_id}</td><td>${sar.subject_name}</td><td>${sar.risk_score}</td><td><span class="badge submitted">${sar.status}</span></td><td>${new Date(sar.created_at).toLocaleString('ar-SA')}</td></tr>`;
                });
                html += '</table>';
                listDiv.innerHTML = html;
            } catch (e) {
                listDiv.innerHTML = '<p>❌ حدث خطأ في تحميل التقارير.</p>';
            }
        }

        async function createCase() {
            const type = document.getElementById('case-type').value;
            const subject = document.getElementById('case-subject').value;
            const priority = document.getElementById('case-priority').value;
            const description = document.getElementById('case-description').value;
            const resultDiv = document.getElementById('case-create-result');
            resultDiv.innerHTML = '⏳ جاري إنشاء الحالة...';
            try {
                const res = await fetch('/cases/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ case_type: type, subject_name: subject, priority: priority, description: description })
                });
                const data = await res.json();
                resultDiv.innerHTML = `<div class="result low"><strong>✅ تم إنشاء الحالة بنجاح!</strong><br>رقم الحالة: <strong>${data.case_id}</strong></div>`;
                loadCases();
            } catch (e) {
                resultDiv.innerHTML = '<div class="result high">❌ حدث خطأ في الاتصال بالخدمة.</div>';
            }
        }

        async function loadCases() {
            const listDiv = document.getElementById('case-list');
            listDiv.innerHTML = '⏳ جاري التحميل...';
            try {
                const res = await fetch('/cases/list?limit=20');
                const data = await res.json();
                if (data.length === 0) {
                    listDiv.innerHTML = '<p>لا توجد حالات حتى الآن.</p>';
                    return;
                }
                let html = '<table><tr><th>رقم الحالة</th><th>النوع</th><th>الاسم</th><th>الأولوية</th><th>الحالة</th><th>التاريخ</th></tr>';
                data.forEach(c => {
                    const statusClass = c.status === 'open' ? 'open' : c.status === 'closed' ? 'closed' : 'submitted';
                    html += `<tr><td>${c.case_id}</td><td>${c.case_type}</td><td>${c.subject_name}</td><td><span class="badge ${c.priority}">${c.priority}</span></td><td><span class="badge ${statusClass}">${c.status}</span></td><td>${new Date(c.created_at).toLocaleString('ar-SA')}</td></tr>`;
                });
                html += '</table>';
                listDiv.innerHTML = html;
            } catch (e) {
                listDiv.innerHTML = '<p>❌ حدث خطأ في تحميل الحالات.</p>';
            }
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML

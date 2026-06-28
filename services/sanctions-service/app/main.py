from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
from urllib.parse import urlparse
import os
import traceback
from datetime import datetime, timedelta
import numpy as np
from sklearn.ensemble import IsolationForest

app = FastAPI(title="Hisn Risk Intelligence Platform", version="2.0.0")

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
        """)
        conn.commit()
        
        # إدراج بيانات عقوبات افتراضية
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

# ============================================================
# بدء التشغيل
# ============================================================
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
# فحص السلامة
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok", "service": "hisn-platform"}

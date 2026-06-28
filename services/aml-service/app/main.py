from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import psycopg2
from urllib.parse import urlparse
import os
import traceback
import numpy as np
from sklearn.ensemble import IsolationForest

app = FastAPI(title="Hisn AML Engine", version="1.0.0")

# قائمة الدول عالية المخاطر (مثال)
HIGH_RISK_COUNTRIES = {"IR", "KP", "SY", "AF", "MM"}

# نموذج Isolation Forest للكشف عن الشذوذ
amounts_model = IsolationForest(contamination=0.1, random_state=42)

# تهيئة النموذج ببيانات تركيبية أولية
X_train = np.random.normal(50000, 20000, 1000).reshape(-1, 1)  # متوسط 50 ألف، انحراف 20 ألف
amounts_model.fit(X_train)

class TransactionRequest(BaseModel):
    customer_id: str
    amount: float
    currency: str = "SAR"
    country: str  # رمز الدولة ISO 3166-1 alpha-2
    transaction_type: str  # "deposit", "withdrawal", "transfer"
    timestamp: Optional[str] = None  # ISO format

class RiskAssessment(BaseModel):
    risk_score: float  # 0.0 إلى 1.0
    risk_level: str  # "low", "medium", "high"
    triggered_rules: List[str] = []

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
        cur.close()
        conn.close()
        print("✅ AML database ready")
    except Exception as e:
        print(f"❌ AML DB init error: {e}")
        traceback.print_exc()

@app.on_event("startup")
async def startup():
    init_db()

@app.post("/aml/evaluate", response_model=RiskAssessment)
async def evaluate_transaction(request: TransactionRequest):
    try:
        conn = get_db()
        cur = conn.cursor()
        risk_score = 0.0
        triggered = []

        # قاعدة 1: مبلغ كبير
        if request.amount > 50000:
            triggered.append("high_amount_exceeds_50k")
            risk_score += 0.4

        # قاعدة 2: دولة عالية المخاطر
        if request.country.upper() in HIGH_RISK_COUNTRIES:
            triggered.append("high_risk_country")
            risk_score += 0.5

        # قاعدة 3: تكرار المعاملات (آخر 10 دقائق)
        if request.timestamp:
            ref_time = datetime.fromisoformat(request.timestamp)
        else:
            ref_time = datetime.utcnow()
        window_start = ref_time - timedelta(minutes=10)
        cur.execute(
            "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = %s AND timestamp >= %s",
            (request.customer_id, window_start)
        )
        recent_count = cur.fetchone()[0]
        if recent_count >= 5:
            triggered.append("rapid_transactions_5_in_10min")
            risk_score += 0.3

        # قاعدة 4: هيكلة الودائع (إيداعات متعددة أقل بقليل من 50 ألف)
        if request.transaction_type == "deposit" and 40000 <= request.amount < 50000:
            # البحث عن إيداعات مماثلة في آخر 24 ساعة
            day_start = ref_time - timedelta(hours=24)
            cur.execute(
                "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = %s AND transaction_type='deposit' AND amount >= 40000 AND amount < 50000 AND timestamp >= %s",
                (request.customer_id, day_start)
            )
            structuring_count = cur.fetchone()[0]
            if structuring_count >= 3:
                triggered.append("possible_structuring_multiple_deposits_below_50k")
                risk_score += 0.6

        # قاعدة 5: نموذج Isolation Forest للشذوذ في المبلغ
        amount_np = np.array([[request.amount]])
        pred = amounts_model.predict(amount_np)[0]
        if pred == -1:  # شاذ
            triggered.append("ml_anomaly_amount")
            risk_score += 0.3

        # تخزين المعاملة
        cur.execute(
            "INSERT INTO hisn.aml_transactions (customer_id, amount, currency, country, transaction_type, timestamp) VALUES (%s, %s, %s, %s, %s, %s)",
            (request.customer_id, request.amount, request.currency, request.country.upper(), request.transaction_type, ref_time)
        )
        conn.commit()
        cur.close()
        conn.close()

        risk_score = min(risk_score, 1.0)
        if risk_score >= 0.7:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"

        return RiskAssessment(
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            triggered_rules=triggered
        )
    except Exception as e:
        print(f"❌ AML evaluation error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error during AML evaluation")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "aml-service"}

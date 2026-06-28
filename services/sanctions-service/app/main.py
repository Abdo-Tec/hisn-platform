from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
from urllib.parse import urlparse
import os
import traceback
from datetime import datetime, timedelta
import numpy as np
from sklearn.ensemble import IsolationForest

app = FastAPI(title="Hisn Risk Intelligence Platform", version="2.2.0")

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
# فحص السلامة
# ============================================================
@app.get("/health")
async def health():
    return {"status": "ok", "service": "hisn-platform"}

# ============================================================
# لوحة التحكم (مضمنة مباشرة)
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
        .sidebar { width: 260px; background: #1e293b; padding: 30px 20px; border-left: 1px solid #334155; }
        .sidebar h2 { color: #f59e0b; margin-bottom: 40px; font-size: 24px; }
        .sidebar button { display: block; width: 100%; padding: 14px; margin-bottom: 12px; background: #334155; color: #e2e8f0; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; transition: 0.3s; }
        .sidebar button.active, .sidebar button:hover { background: #f59e0b; color: #0f172a; font-weight: bold; }
        .main { flex: 1; padding: 40px; }
        .section { display: none; }
        .section.active { display: block; }
        .card { background: #1e293b; padding: 30px; border-radius: 16px; margin-bottom: 20px; border: 1px solid #334155; }
        .card h3 { margin-bottom: 20px; color: #f59e0b; }
        .form-group { margin-bottom: 18px; }
        label { display: block; margin-bottom: 6px; color: #94a3b8; }
        input, select { width: 100%; padding: 12px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #e2e8f0; font-size: 16px; }
        button.submit { padding: 12px 30px; background: #f59e0b; color: #0f172a; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; }
        .result { margin-top: 20px; padding: 20px; border-radius: 8px; }
        .result.high { background: #7f1d1d; border: 1px solid #ef4444; }
        .result.medium { background: #78350f; border: 1px solid #f59e0b; }
        .result.low { background: #14532d; border: 1px solid #22c55e; }
        .result.match { background: #7f1d1d; border: 1px solid #ef4444; }
        .result.no-match { background: #14532d; border: 1px solid #22c55e; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 14px; margin: 4px; }
        .badge.rule { background: #f59e0b; color: #0f172a; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>🛡️ حِصْن</h2>
        <button class="active" onclick="showSection('sanctions')">🔍 فحص العقوبات</button>
        <button onclick="showSection('aml')">💰 تقييم AML</button>
    </div>
    <div class="main">
        <div id="section-sanctions" class="section active">
            <div class="card">
                <h3>🔍 فحص قوائم العقوبات</h3>
                <div class="form-group"><label>الاسم الكامل</label><input type="text" id="sanction-name" placeholder="أدخل الاسم للفحص..."></div>
                <div class="form-group"><label>اللغة</label><select id="sanction-lang"><option value="ar">العربية</option><option value="en">الإنجليزية</option></select></div>
                <button class="submit" onclick="checkSanctions()">فحص</button>
                <div id="sanction-result"></div>
            </div>
        </div>
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
    </div>
    <script>
        function showSection(section) {
            document.querySelectorAll('.section').forEach(el => el.classList.remove('active'));
            document.getElementById('section-' + section).classList.add('active');
            document.querySelectorAll('.sidebar button').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
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
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
from urllib.parse import urlparse
import os
import traceback

app = FastAPI(title="Hisn Sanctions Service", version="1.2.0")

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

def get_db():
    db_url = os.getenv("DATABASE_URL")
    if db_url is None:
        raise HTTPException(status_code=500, detail="DATABASE_URL environment variable is not set!")
    result = urlparse(db_url)
    conn = psycopg2.connect(
        database=result.path[1:],
        user=result.username,
        password=result.password,
        host=result.hostname,
        port=result.port
    )
    return conn

def init_db():
    """تهيئة قاعدة البيانات وإدراج بيانات تجريبية إذا كانت فارغة"""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # إنشاء الجداول
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
        """)
        conn.commit()
        
        # التحقق مما إذا كان الجدول فارغاً
        cur.execute("SELECT COUNT(*) FROM hisn.watchlist")
        count = cur.fetchone()[0]
        
        if count == 0:
            print("📝 إدراج بيانات عقوبات افتراضية...")
            cur.execute("""
                INSERT INTO hisn.watchlist (full_name_ar, full_name_en, list_type) VALUES
                ('أسامة بن لادن', 'Osama bin Laden', 'UN'),
                ('أيمن الظواهري', 'Ayman al-Zawahiri', 'UN'),
                ('أبو بكر البغدادي', 'Abu Bakr al-Baghdadi', 'UN'),
                ('قاسم الريمي', 'Qasim al-Raymi', 'UN'),
                ('محمد الضالع', 'Mohammed al-Dhale', 'UN'),
                ('سعيد الشهري', 'Saeed al-Shehri', 'UN'),
                ('عبد الله المحيسني', 'Abdullah al-Muhaysini', 'UN'),
                ('إبراهيم الربيش', 'Ibrahim al-Rubaysh', 'UN')
            """)
            conn.commit()
            print("✅ تم إدراج بيانات العقوبات بنجاح")
        
        cur.close()
        conn.close()
        print("✅ تم تجهيز قاعدة البيانات بنجاح")
    except Exception as e:
        print(f"❌ خطأ في تهيئة قاعدة البيانات: {e}")
        traceback.print_exc()

@app.on_event("startup")
async def startup_event():
    init_db()

@app.post("/sanctions/check", response_model=SanctionCheckResponse)
async def check_sanctions(
    request: SanctionCheckRequest,
    x_api_key: str = Header(...),
    x_tenant_id: str = Header(...)
):
    try:
        conn = get_db()
        cur = conn.cursor()
        
        if request.language == "ar":
            cur.execute(
                "SELECT full_name_ar, full_name_en, list_type FROM hisn.watchlist WHERE full_name_ar ILIKE %s",
                (f"%{request.full_name}%",)
            )
        else:
            cur.execute(
                "SELECT full_name_ar, full_name_en, list_type FROM hisn.watchlist WHERE full_name_en ILIKE %s",
                (f"%{request.full_name}%",)
            )
        
        results = cur.fetchall()
        cur.close()
        conn.close()
        
        matches = [
            MatchResult(
                matched_name=row[1] or row[0],
                list_type=row[2],
                score=1.0
            )
            for row in results
        ]
        
        return SanctionCheckResponse(
            is_match=len(matches) > 0,
            matches=matches
        )
    except Exception as e:
        print(f"❌ خطأ في فحص العقوبات: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "sanctions-service"}

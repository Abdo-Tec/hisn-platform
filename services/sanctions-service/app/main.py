import os
import sys
import traceback
from urllib.parse import urlparse
from typing import List, Optional

import psycopg2
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

# إعداد التطبيق
app = FastAPI(title="Hisn Sanctions Service", version="1.1.0")

# ------------- النماذج (Models) -------------
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

# ------------- دوال قاعدة البيانات -------------
def get_database_url():
    """الحصول على رابط قاعدة البيانات من متغيرات البيئة"""
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("❌ متغير البيئة DATABASE_URL غير موجود!")
    return db_url

def get_db_connection():
    """إنشاء اتصال بقاعدة البيانات"""
    db_url = get_database_url()
    result = urlparse(db_url)
    return psycopg2.connect(
        database=result.path[1:],
        user=result.username,
        password=result.password,
        host=result.hostname,
        port=result.port
    )

def init_db():
    """تهيئة قاعدة البيانات وإنشاء الجداول"""
    try:
        print("🔄 جاري تهيئة قاعدة البيانات...")
        conn = get_db_connection()
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
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("✅ تم تجهيز قاعدة البيانات بنجاح")
        return True
    except Exception as e:
        print(f"❌ فشل تهيئة قاعدة البيانات: {e}")
        traceback.print_exc()
        return False

# ------------- نقاط النهاية (API Endpoints) -------------
@app.on_event("startup")
async def startup():
    """يتم تنفيذها عند بدء تشغيل التطبيق"""
    print("🚀 بدء تشغيل خدمة فحص العقوبات...")
    db_ok = init_db()
    if not db_ok:
        print("⚠️ تحذير: الخدمة تعمل ولكن قاعدة البيانات غير جاهزة")

@app.get("/health")
async def health():
    """نقطة فحص السلامة"""
    return {"status": "ok", "service": "sanctions-service"}

@app.post("/sanctions/check", response_model=SanctionCheckResponse)
async def check_sanctions(
    request: SanctionCheckRequest,
    x_api_key: str = Header(...),
    x_tenant_id: str = Header(...)
):
    """فحص اسم مقابل قوائم العقوبات"""
    try:
        conn = get_db_connection()
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
        raise HTTPException(status_code=500, detail="Internal server error during sanctions check")

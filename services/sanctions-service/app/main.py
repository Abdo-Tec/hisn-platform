from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Hisn Sanctions Service", version="1.0.0")

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
    conn = psycopg2.connect(
        host="postgres",
        database=os.getenv("POSTGRES_DB", "hisn_db"),
        user=os.getenv("POSTGRES_USER", "hisn_user"),
        password=os.getenv("POSTGRES_PASSWORD", "Hisn@2026!Secure")
    )
    return conn

@app.post("/sanctions/check", response_model=SanctionCheckResponse)
async def check_sanctions(
    request: SanctionCheckRequest,
    x_api_key: str = Header(...),
    x_tenant_id: str = Header(...)
):
    # In production, validate API key and tenant
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

@app.get("/health")
async def health():
    return {"status": "ok", "service": "sanctions-service"}

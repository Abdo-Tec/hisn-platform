Skip to content
Abdo-Tec
hisn-platform
Repository navigation
Code
Issues
Pull requests
1
 (1)
Actions
Projects
Wiki
Security and quality
Insights
Settings
Commit 0b2e95d
railway-app[bot]
railway-app[bot]
authored
18 hours ago
·
·
Verified
fix: remove bare psycopg2.connect call in sanctions-service main.py
main(#2)
1 parent 
61dc4f8
 commit 
0b2e95d
1 file changed

-6
Lines changed: 0 additions & 6 deletions
File tree
Filter files…
services/sanctions-service/app
main.py
Search within code
 
‎services/sanctions-service/app/main.py‎
-6
Lines changed: 0 additions & 6 deletions
Original file line number	Diff line number	Diff line change
@@ -73,9 +73,3 @@ async def check_sanctions(
@app.get("/health")
async def health():
    return {"status": "ok", "service": "sanctions-service"}
conn = psycopg2.connect(
    host="postgres",
    database=os.getenv("POSTGRES_DB", "hisn_db"),
    user=os.getenv("POSTGRES_USER", "hisn_user"),
    password=os.getenv("POSTGRES_PASSWORD", "Hisn@2026!Secure")
)
0 commit comments
Comments
0
 (0)
Comment
You're not receiving notifications from this thread.


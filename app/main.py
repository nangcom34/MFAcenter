import os
import urllib.parse
import httpx
from fastapi import FastAPI, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.schemas import User, TargetApplication
from app.routers import auth, admin

app = FastAPI(
    title="DLD-MFAcenter",
    description="Multi-Factor Authentication Proxy Gateway - Department of Livestock Development",
    version="1.0.0"
)

# 📂 Mount Static Files สำหรับหน้า Login/Admin ของ MFAcenter
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/mfa_static", StaticFiles(directory=static_dir), name="mfa_static")

templates = Jinja2Templates(directory="app/templates")

# 🔑 ลงทะเบียน Routers ของระบบ MFA ( auth & admin )
app.include_router(auth.router)
app.include_router(admin.router)

# [ฟังก์ชันที่ 1] Health Check Endpoint
@app.get("/health", tags=["Health Check"])
async def health_check():
    return {"status": "ok", "service": "DLD-MFAcenter Reverse Proxy Gateway"}

# ------------------------------------------------------------------------------
# 🌐 Main Gateway & Transparent Catch-All Reverse Proxy Handler
# ------------------------------------------------------------------------------

# [ฟังก์ชันที่ 2] Transparent Catch-All Proxy (ส่งผ่านทุก Path, Method, Headers, Cookies ไปยัง Backend Target)
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def main_gateway(request: Request, full_path: str = "", db: AsyncSession = Depends(get_db)):
    user_session = request.cookies.get("user_session")

    # 1. หากยังไม่ได้ผ่าน MFA ให้แสดงหน้า User Login HTML ของ MFAcenter
    if not user_session:
        try:
            return templates.TemplateResponse(request=request, name="auth/login.html")
        except Exception:
            return templates.TemplateResponse(request=request, name="login.html")

    # 2. ตรวจสอบ Session MFA ในฐานข้อมูล
    result = await db.execute(select(User).where(User.id == user_session))
    user_obj = result.scalar_one_or_none()

    if not user_obj:
        response = templates.TemplateResponse(request=request, name="auth/login.html")
        response.delete_cookie(key="user_session", path="/")
        return response

    # 3. ค้นหาระบบงานปลายทาง (TargetApplication)
    host_header = request.headers.get("host", "").split(":")[0]
    app_obj = None

    if getattr(user_obj, "app_id", None):
        app_res = await db.execute(select(TargetApplication).where(TargetApplication.id == user_obj.app_id))
        app_obj = app_res.scalar_one_or_none()

    if not app_obj:
        app_res = await db.execute(select(TargetApplication).where(TargetApplication.public_domain == host_header))
        app_obj = app_res.scalar_one_or_none()

    # 4. กำหนด Backend Target URL หลัก
    target_base_url = "https://httpbin.org"  # Fallback
    if app_obj:
        raw_target = getattr(app_obj, "backend_target_url", None) or getattr(app_obj, "backend_url", None)
        if raw_target:
            if raw_target.startswith("http://") or raw_target.startswith("https://"):
                target_base_url = raw_target.rstrip("/")
            else:
                target_base_url = f"http://{raw_target}".rstrip("/")

    # ประกอบ URL ปลายทางอย่างสมบูรณ์ (รักษา Sub-path และ Query Parameters ของระบบปลายทางไว้ทั้งหมด)
    proxy_target_url = f"{target_base_url}/{full_path}"
    if request.url.query:
        proxy_target_url += f"?{request.url.query}"

    # 5. ปรับแต่ง Forward Headers ให้ระบบปลายทางรับรู้ Host และ Client IP ที่แท้จริง
    parsed_target = urllib.parse.urlparse(target_base_url)
    target_host = parsed_target.netloc

    req_headers = dict(request.headers)
    req_headers["host"] = target_host
    req_headers["x-forwarded-host"] = host_header
    req_headers["x-forwarded-for"] = request.client.host if request.client else "127.0.0.1"
    req_headers["x-forwarded-proto"] = request.url.scheme

    body = await request.body()

    # 6. ทำการ Proxy Request และส่งผ่าน Response กลับมาแบบละเอียดยิบ
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        try:
            proxy_res = await client.request(
                method=request.method,
                url=proxy_target_url,
                headers=req_headers,
                content=body
            )

            res = Response(content=proxy_res.content, status_code=proxy_res.status_code)
            excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}

            # ส่งต่อ Headers ทั้งหมดจาก Backend (รวมถึง Set-Cookie สำหรับ Login ของระบบจริง)
            for name, value in proxy_res.headers.raw:
                header_name = name.decode("latin1")
                if header_name.lower() not in excluded_headers:
                    res.headers.append(header_name, value.decode("latin1"))

            return res
        except Exception as e:
            return Response(
                content=f"<h1>Proxy Gateway Error</h1><p>Cannot connect to backend target '{proxy_target_url}': {e}</p>",
                status_code=502,
                media_type="text/html"
            )
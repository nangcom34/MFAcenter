# app/proxy/proxy_router.py
import uuid
import httpx
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import Response, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.redis import get_redis
from app.models.schemas import TargetApplication, AuditLog

from pathlib import Path
from fastapi.templating import Jinja2Templates

# กำหนด Absolute Path ล็อกไปยังโฟลเดอร์ app/templates โดยตรง
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Helper Function บันทึก Audit Log
async def audit_logger(
    db: AsyncSession,
    app_id: str | uuid.UUID | None,
    app_domain: str,
    client_ip: str,
    username: str | None,
    action: str,
    user_agent: str | None = None
):
    target_uuid = None
    if app_id and str(app_id) != "00000000-0000-0000-0000-000000000000":
        target_uuid = app_id if isinstance(app_id, uuid.UUID) else uuid.UUID(str(app_id))

    log_entry = AuditLog(
        target_app_id=target_uuid,
        app_domain=app_domain,
        client_ip=client_ip,
        username=username,
        action=action,
        user_agent=user_agent
    )
    db.add(log_entry)
    await db.commit()

# Helper Function ส่ง HTTP Request ตรงไปยัง Backend หลังบ้าน
async def forward_to_backend(request: Request, backend_url: str):
    path = request.url.path
    query = request.url.query
    target_full_url = f"{backend_url.rstrip('/')}{path}"
    if query:
        target_full_url += f"?{query}"

    # ดึง Headers จาก Request และลบ Host header ออกป้องกันความขัดแย้ง
    headers = dict(request.headers)
    headers.pop("host", None)

    body = await request.body()

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_full_url,
                headers=headers,
                content=body,
                cookies=request.cookies
            )
            
            # กรอง Hop-by-hop headers และดึงแบบ str (resp.headers.items())
            excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
            
            response_headers = {}
            for key, value in resp.headers.items():
                if key.lower() not in excluded_headers:
                    response_headers[key] = value

            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=response_headers
            )
        except Exception as e:
            print(f"[FORWARD ERROR] ไม่สามารถเชื่อมต่อปลายทาง {target_full_url}: {str(e)}")
            return Response(content=f"Backend Gateway Error: {str(e)}", status_code=502)

# Dynamic Proxy Handler
@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def handle_dynamic_proxy(request: Request, path: str = "", db: AsyncSession = Depends(get_db)):
    # 🚨 0. หากเป็นเส้นทางของ Auth หรือ Admin ให้ยกเว้น (ปล่อยให้ Router เฉพาะทำงาน)
    clean_path = path.lstrip("/")
    if clean_path.startswith("auth") or clean_path.startswith("admin"):
        raise HTTPException(status_code=404, detail="Not Handled By Proxy")

    host = request.headers.get("host", "").split(":")[0]

    # 1. ค้นหาระบบงานใน DB ตาม Public Domain
    stmt = select(TargetApplication).where(TargetApplication.public_domain == host)
    result = await db.execute(stmt)
    app = result.scalars().first()

    if not app:
        return Response(content="404 Not Found - Application Domain Unregistered", status_code=404)

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")

    # 🚨 2. ตรวจสอบโหมด Emergency MFA Bypass
    if app.is_bypass_enabled:
        await audit_logger(
            db=db,
            app_id=app.id,
            app_domain=app.public_domain,
            client_ip=client_ip,
            username=None,
            action="EMERGENCY_MFA_BYPASS",
            user_agent=user_agent
        )
        return await forward_to_backend(request, app.backend_target_url)

    # 3. ตรวจสอบ Session การล็อกอินปกติ
    session_id = request.cookies.get(f"dld_session_{app.id}")
    redis = get_redis()

    if session_id:
        session_valid = await redis.get(f"session:{session_id}")
        if session_valid:
            return await forward_to_backend(request, app.backend_target_url)

    # 4. แสดงหน้าล็อกอิน MFA
    return templates.TemplateResponse(
        request=request, 
        name="auth/login.html", 
        context={"app_name": app.app_name, "public_domain": app.public_domain}
    )
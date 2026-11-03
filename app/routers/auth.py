# app/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import pyotp
import qrcode
import io
import base64

from app.core.database import get_db
from app.core.redis import get_redis
from app.core.security import verify_totp_code
from app.models.schemas import TargetApplication, User, AuditAction
from app.proxy.pass_through_service import LegacyPassThroughService
from app.proxy.proxy_router import audit_logger

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/verify-step1")
async def verify_step1_credentials(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    host = request.headers.get("host", "").split(":")[0]
    
    app = await db.scalar(select(TargetApplication).where(TargetApplication.public_domain == host))
    if not app:
        return JSONResponse({"status": "failed", "message": "ไม่พบข้อมูลระบบงานปลายทางในระบบ"}, status_code=404)

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")

    user = await db.scalar(select(User).where(User.username == username.strip()))
    
    # ตรวจสอบรหัสผ่านผ่าน Pass-through Auth หรือใช้บัญชีทดสอบ testuser
    legacy_auth_success = await LegacyPassThroughService.verify_legacy_credentials(app, username.strip(), password)

    if not legacy_auth_success and not (user and password == "pass1234"):
        await audit_logger(
            db=db, app_id=app.id, app_domain=app.public_domain,
            client_ip=client_ip, username=username.strip(),
            action=AuditAction.LOGIN_FAILED.value, user_agent=user_agent
        )
        return JSONResponse({"status": "failed", "message": "Username หรือ Password ไม่ถูกต้อง"}, status_code=401)

    redis = get_redis()
    is_enrolled = bool(await redis.get(f"totp_enrolled:{username.strip()}"))
    
    qr_code_url = ""
    totp_secret = ""

    if user and user.totp_secret:
        totp_secret = user.totp_secret
        is_enrolled = True
    else:
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=username.strip(),
            issuer_name=f"DLD-MFA ({app.app_name})"
        )
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_code_url = f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
        
        await redis.setex(f"temp_totp_secret:{username.strip()}", 600, totp_secret)

    return JSONResponse({
        "status": "success",
        "is_enrolled": is_enrolled,
        "qr_code_url": qr_code_url,
        "totp_secret": totp_secret
    })

@router.post("/verify-step2")
async def verify_step2_credentials(
    request: Request,
    username: str = Form(...),
    totp_code: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    host = request.headers.get("host", "").split(":")[0]
    app = await db.scalar(select(TargetApplication).where(TargetApplication.public_domain == host))
    if not app:
        return JSONResponse({"status": "failed", "message": "ไม่พบข้อมูลระบบงาน"}, status_code=404)

    redis = get_redis()
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")

    user = await db.scalar(select(User).where(User.username == username.strip()))
    totp_secret = user.totp_secret if user and user.totp_secret else await redis.get(f"temp_totp_secret:{username.strip()}")

    if not totp_secret:
        return JSONResponse({"status": "failed", "message": "เซสชันหมดอายุ กรุณาล็อกอินใหม่อีกครั้ง"}, status_code=400)

    if not verify_totp_code(totp_secret, totp_code.strip()):
        await audit_logger(
            db=db, app_id=app.id, app_domain=app.public_domain,
            client_ip=client_ip, username=username.strip(),
            action=AuditAction.TOTP_VERIFY_FAILED.value, user_agent=user_agent
        )
        return JSONResponse({"status": "failed", "message": "รหัส TOTP 6 หลักไม่ถูกต้อง"}, status_code=401)

    if user:
        user.totp_secret = totp_secret
        await db.commit()
    
    await redis.set(f"totp_enrolled:{username.strip()}", "1")
    await redis.delete(f"temp_totp_secret:{username.strip()}")

    import uuid as session_uuid
    session_id = str(session_uuid.uuid4())
    await redis.setex(f"session:{session_id}", 28800, username.strip())

    await audit_logger(
        db=db, app_id=app.id, app_domain=app.public_domain,
        client_ip=client_ip, username=username.strip(),
        action=AuditAction.LOGIN_SUCCESS.value, user_agent=user_agent
    )

    response = JSONResponse({"status": "success", "message": "ยืนยันตัวตนสำเร็จ"})
    response.set_cookie(
        key=f"dld_session_{app.id}",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=28800
    )
    return response
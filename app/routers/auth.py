import uuid
import pyotp
import urllib.parse
from datetime import datetime
from typing import Dict, Any

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Form, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.schemas import User, TargetApplication, AuditLog, AuditAction

# ------------------------------------------------------------------------------
# 🛠️ Security Helpers
# ------------------------------------------------------------------------------


# [ฟังก์ชันที่ 1] ตรวจสอบรหัสผ่านของ User ด้วย bcrypt โดยตรง
def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    pwd_bytes = plain_password.encode("utf-8")[:72]
    try:
        return bcrypt.checkpw(pwd_bytes, hashed_password.encode("utf-8"))
    except Exception:
        return False


# ------------------------------------------------------------------------------
# 🚀 APIRouter Setup
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["User Auth"])
temp_user_tokens: Dict[str, Dict[str, Any]] = {}

# ------------------------------------------------------------------------------
# 🌐 User Authentication Endpoints
# ------------------------------------------------------------------------------


# [ฟังก์ชันที่ 2] User Step 1 - ตรวจสอบ Username, Password, สถานะ MFA Bypass และออก QR Code
@router.post("/verify-step1")
async def user_verify_step1(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    host_header = request.headers.get("host", "").split(":")[0]

    result = await db.execute(select(User).where(User.username == username))
    user_obj = result.scalar_one_or_none()

    if not user_obj:
        raise HTTPException(status_code=401, detail="Username หรือ Password ไม่ถูกต้อง")

    current_hash = (
        getattr(user_obj, "password_hash", None)
        or getattr(user_obj, "hashed_password", None)
        or getattr(user_obj, "password", None)
    )

    if not current_hash or not verify_password(password, current_hash):
        raise HTTPException(status_code=401, detail="Username หรือ Password ไม่ถูกต้อง")

    # ตรวจสอบสถานะ MFA Bypass ของแอปปลายทาง
    app_res = await db.execute(
        select(TargetApplication).where(TargetApplication.id == user_obj.app_id)
    )
    app_obj = app_res.scalar_one_or_none()

    if app_obj and getattr(app_obj, "is_bypass_enabled", False):
        return {"success": True, "bypass": True, "redirect_url": "/"}

    existing_secret = getattr(user_obj, "totp_secret", None)
    is_first_time = not bool(existing_secret)

    totp_secret = pyotp.random_base32() if is_first_time else existing_secret
    totp = pyotp.TOTP(totp_secret)
    app_title = app_obj.app_name if app_obj else "DLD-MFAcenter"
    provisioning_uri = totp.provisioning_uri(
        name=user_obj.username, issuer_name=f"DLD-MFA ({app_title})"
    )
    qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(provisioning_uri)}"

    temp_token = str(uuid.uuid4())
    temp_user_tokens[temp_token] = {
        "user_id": str(user_obj.id),
        "username": user_obj.username,
        "totp_secret": totp_secret,
        "is_first_time": is_first_time,
        "app_domain": host_header,
        "created_at": datetime.utcnow(),
    }

    return {
        "success": True,
        "temp_token": temp_token,
        "is_first_time": is_first_time,
        "totp_secret": totp_secret if is_first_time else None,
        "qr_code_url": qr_code_url if is_first_time else None,
    }


# [ฟังก์ชันที่ 3] User Step 2 - ยืนยันรหัส OTP 6 หลัก และลงบันทึก Audit Log
@router.post("/verify-step2")
async def user_verify_step2(
    request: Request,
    response: Response,
    temp_token: str = Form(default=""),
    totp_code: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
):
    if not temp_token or not totp_code:
        raise HTTPException(
            status_code=400, detail="กรุณากรอกรหัส OTP 6 หลักให้ครบถ้วน"
        )

    token_data = temp_user_tokens.get(temp_token)
    if not token_data:
        raise HTTPException(
            status_code=401, detail="Session หมดอายุ กรุณาเข้าสู่ระบบใหม่อีกครั้ง"
        )

    totp_secret = token_data["totp_secret"]
    totp = pyotp.TOTP(totp_secret)

    if not totp.verify(totp_code):
        raise HTTPException(
            status_code=400, detail="รหัส OTP 6 หลักไม่ถูกต้องหรือหมดอายุ"
        )

    if token_data.get("is_first_time"):
        user_res = await db.execute(
            select(User).where(User.id == token_data["user_id"])
        )
        user_obj = user_res.scalar_one_or_none()
        if user_obj:
            user_obj.totp_secret = totp_secret
            if hasattr(user_obj, "is_mfa_enrolled"):
                user_obj.is_mfa_enrolled = True
            await db.commit()

    # บันทึก Audit Log การเข้าสู่ระบบสำเร็จ
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_log = AuditLog(
        timestamp=datetime.utcnow(),
        app_domain=token_data.get("app_domain", "-"),
        client_ip=client_ip,
        username=token_data["username"],
        action=getattr(AuditAction, "MFA_VERIFIED", "MFA_VERIFIED"),
    )
    db.add(audit_log)
    await db.commit()

    del temp_user_tokens[temp_token]

    response.set_cookie(
        key="user_session",
        value=token_data["user_id"],
        httponly=True,
        samesite="lax",
        path="/",
    )
    return {"success": True, "redirect_url": "/"}


# [ฟังก์ชันที่ 4] API ออกจากระบบผู้ใช้งานทั่วไป (User Logout)
@router.get("/logout", response_class=RedirectResponse)
async def user_logout(response: Response):
    res = RedirectResponse(url="/", status_code=302)
    res.delete_cookie(key="user_session", path="/")
    return res

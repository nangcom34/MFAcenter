import uuid
import pyotp
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Form, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.core.database import get_db
from app.models.schemas import User, TargetApplication, AuditLog, AuditAction

# ------------------------------------------------------------------------------
# 🛠️ Security Helpers (Flexible Multi-Format Password Verification)
# ------------------------------------------------------------------------------

# [ฟังก์ชันที่ 1] ตรวจสอบรหัสผ่านของ User รองรับทั้ง Bcrypt ($2b$, $2y$, $2a$) และ Plain Text
def verify_password(plain_password: str, hashed_password: Any) -> bool:
    if not plain_password or not hashed_password:
        return False

    plain_clean = plain_password.strip()

    if isinstance(hashed_password, bytes):
        hash_str = hashed_password.decode('utf-8', errors='ignore').strip()
    else:
        hash_str = str(hashed_password).strip()

    # 1. เปรียบเทียบแบบ Plain Text Direct Match
    if plain_clean == hash_str or plain_password == hash_str:
        return True

    # 2. ตรวจสอบด้วย bcrypt แบบมาตรฐาน
    pwd_bytes = plain_clean.encode('utf-8')[:72]
    try:
        if bcrypt.checkpw(pwd_bytes, hash_str.encode('utf-8')):
            return True
    except Exception:
        pass

    # 3. แปลง Prefix $2y$ และ $2a$ เป็น $2b$ (รองรับ Passlib / Legacy Hashes)
    if hash_str.startswith("$2y$") or hash_str.startswith("$2a$"):
        try:
            alt_hash = "$2b$" + hash_str[4:]
            if bcrypt.checkpw(pwd_bytes, alt_hash.encode('utf-8')):
                return True
        except Exception:
            pass

    return False

# ------------------------------------------------------------------------------
# 🚀 APIRouter & State Setup
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/auth", tags=["User Auth"])
temp_user_tokens: Dict[str, Dict[str, Any]] = {}

# ------------------------------------------------------------------------------
# 🌐 User Authentication Endpoints
# ------------------------------------------------------------------------------

# [ฟังก์ชันที่ 2] User Step 1 - ตรวจสอบ Username / รหัสบัตรประชาชน และออก QR Code ผูก MFA ครั้งแรก
@router.post("/verify-step1")
async def user_verify_step1(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    clean_identifier = username.strip()
    host_header = request.headers.get("host", "").split(":")[0]
    
    # 1. ค้นหาระบบงานปลายทาง (TargetApplication) จาก Host Header
    app_res = await db.execute(select(TargetApplication).where(TargetApplication.public_domain == host_header))
    app_obj = app_res.scalar_one_or_none()

    # 🔑 2. สร้าง Dynamic Query ค้นหาจากทั้ง username, citizen_id, cid, id_card, email (ตาม Column ที่มีจริงใน Model)
    possible_identifier_cols = ["username", "citizen_id", "cid", "id_card", "email", "user_id"]
    active_filters = []
    
    for col_name in possible_identifier_cols:
        if hasattr(User, col_name):
            active_filters.append(func.lower(getattr(User, col_name)) == clean_identifier.lower())

    if not active_filters:
        # Fallback กรณีไม่มีคอลัมน์อื่น ให้ใช้ username
        active_filters.append(func.lower(User.username) == clean_identifier.lower())

    # กรองเฉพาะ User ในระบบงานนี้ หรือ User ส่วนกลาง (app_id is None)
    stmt = select(User).where(or_(*active_filters))
    if app_obj:
        stmt = stmt.where(or_(User.app_id == app_obj.id, User.app_id.is_(None)))

    result = await db.execute(stmt)
    users = result.scalars().all()

    # Fallback กรณีไม่พบคู่แอป ให้ค้นหาแบบ Global จากทุก Record
    if not users:
        result = await db.execute(select(User).where(or_(*active_filters)))
        users = result.scalars().all()

    if not users:
        raise HTTPException(status_code=401, detail="ชื่อผู้ใช้งาน/เลขบัตรประชาชน หรือรหัสผ่านไม่ถูกต้อง")

    # 🔑 3. วนลูปตรวจสอบรหัสผ่านกับทุก Field Password ที่อาจมีในคลาส User
    possible_password_cols = ["password_hash", "hashed_password", "password", "pwd", "pass_hash"]
    user_obj = None

    for candidate in users:
        current_hash = None
        for p_col in possible_password_cols:
            val = getattr(candidate, p_col, None)
            if val:
                current_hash = val
                break

        if current_hash and verify_password(password, current_hash):
            user_obj = candidate
            break

    if not user_obj:
        raise HTTPException(status_code=401, detail="ชื่อผู้ใช้งาน/เลขบัตรประชาชน หรือรหัสผ่านไม่ถูกต้อง")

    # 4. หากยังไม่ได้ดึง app_obj ให้ดึงตาม app_id ของ User
    if not app_obj and getattr(user_obj, "app_id", None):
        app_res = await db.execute(select(TargetApplication).where(TargetApplication.id == user_obj.app_id))
        app_obj = app_res.scalar_one_or_none()

    # 5. ตรวจสอบสถานะ Emergency MFA Bypass
    if app_obj and getattr(app_obj, "is_bypass_enabled", False):
        return {"success": True, "bypass": True, "redirect_url": "/"}

    # 6. ตรวจสอบสถานะ TOTP Enrolment
    existing_secret = getattr(user_obj, "totp_secret", None)
    is_first_time = not bool(existing_secret)

    totp_secret = pyotp.random_base32() if is_first_time else existing_secret
    totp = pyotp.TOTP(totp_secret)
    app_title = app_obj.app_name if app_obj else "DLD-MFAcenter"
    provisioning_uri = totp.provisioning_uri(name=user_obj.username, issuer_name=f"DLD-MFA ({app_title})")
    qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(provisioning_uri)}"

    temp_token = str(uuid.uuid4())
    temp_user_tokens[temp_token] = {
        "user_id": str(user_obj.id),
        "username": user_obj.username,
        "totp_secret": totp_secret,
        "is_first_time": is_first_time,
        "app_domain": host_header,
        "created_at": datetime.utcnow()
    }

    return {
        "success": True,
        "temp_token": temp_token,
        "is_first_time": is_first_time,
        "totp_secret": totp_secret if is_first_time else None,
        "qr_code_url": qr_code_url if is_first_time else None
    }

# [ฟังก์ชันที่ 3] User Step 2 - ยืนยัน OTP 6 หลัก และส่งกลับหน้า Root Proxy (/)
@router.post("/verify-step2")
async def user_verify_step2(
    request: Request,
    response: Response,
    temp_token: str = Form(default=""),
    totp_code: str = Form(default=""),
    db: AsyncSession = Depends(get_db)
):
    if not temp_token or not totp_code:
        raise HTTPException(status_code=400, detail="กรุณากรอกรหัส OTP 6 หลักให้ครบถ้วน")

    token_data = temp_user_tokens.get(temp_token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Session หมดอายุ กรุณาเข้าสู่ระบบใหม่อีกครั้ง")

    totp_secret = token_data["totp_secret"]
    totp = pyotp.TOTP(totp_secret)

    if not totp.verify(totp_code):
        raise HTTPException(status_code=400, detail="รหัส OTP 6 หลักไม่ถูกต้องหรือหมดอายุ")

    if token_data.get("is_first_time"):
        user_res = await db.execute(select(User).where(User.id == token_data["user_id"]))
        user_obj = user_res.scalar_one_or_none()
        if user_obj:
            user_obj.totp_secret = totp_secret
            if hasattr(user_obj, "is_mfa_enrolled"):
                user_obj.is_mfa_enrolled = True
            await db.commit()

    # บันทึก Audit Log
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_log = AuditLog(
        timestamp=datetime.utcnow(),
        app_domain=token_data.get("app_domain", "-"),
        client_ip=client_ip,
        username=token_data["username"],
        action=getattr(AuditAction, "MFA_VERIFIED", "MFA_VERIFIED")
    )
    db.add(audit_log)
    await db.commit()

    del temp_user_tokens[temp_token]

    response.set_cookie(key="user_session", value=token_data["user_id"], httponly=True, samesite="lax", path="/")
    return {"success": True, "redirect_url": "/"}

# [ฟังก์ชันที่ 4] API ออกจากระบบผู้ใช้งานทั่วไป (User Logout)
@router.get("/logout", response_class=RedirectResponse)
async def user_logout(response: Response):
    res = RedirectResponse(url="/", status_code=302)
    res.delete_cookie(key="user_session", path="/")
    return res
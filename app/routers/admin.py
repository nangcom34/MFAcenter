import uuid
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import bcrypt
import pyotp
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete, String

# ------------------------------------------------------------------------------
# 🔑 Safe Fallback Imports (สำหรับ Database Connection, Dependencies & Models)
# ------------------------------------------------------------------------------
try:
    from app.core.database import get_db
except (ImportError, ModuleNotFoundError):
    try:
        from app.database import get_db
    except (ImportError, ModuleNotFoundError):
        from app.routers.auth import get_db

try:
    from app.models.schemas import TargetApplication, User, AuditLog, UserRole
except (ImportError, ModuleNotFoundError):
    from app.models import TargetApplication, User, AuditLog, UserRole

# ------------------------------------------------------------------------------
# 🛠️ Helper Functions & Security Dependencies
# ------------------------------------------------------------------------------


# [ฟังก์ชันที่ 1] ตรวจสอบรหัสผ่านผ่าน bcrypt โดยตรง (ตัดความยาวป้องกัน ValueError)
def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    pwd_bytes = plain_password.encode("utf-8")[:72]
    try:
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


# [ฟังก์ชันที่ 2] เข้ารหัสพาสเวิร์ดใหม่ด้วย bcrypt
def get_password_hash(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


# [ฟังก์ชันที่ 3] แปลงข้อมูลผู้ใช้งานให้อยู่ในรูปแบบ Dictionary มาตรฐาน
def extract_user_info(user: Any) -> Dict[str, Any]:
    if isinstance(user, dict):
        return {
            "id": str(user.get("id", "")),
            "username": user.get("username", "Admin"),
            "role": str(user.get("role", "SUPERADMIN")),
            "app_id": user.get("app_id"),
        }
    role_val = getattr(user, "role", "SUPERADMIN")
    role_str = str(role_val.value if hasattr(role_val, "value") else role_val)
    return {
        "id": str(getattr(user, "id", "")),
        "username": getattr(user, "username", "Admin"),
        "role": role_str,
        "app_id": getattr(user, "app_id", None),
    }


# [ฟังก์ชันที่ 4] Dependency สำหรับตรวจเช็ก Session Cookie และสิทธิ์การใช้งาน Admin
async def get_current_admin(request: Request, db: AsyncSession = Depends(get_db)):
    session_id = request.cookies.get("session")
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="กรุณาเข้าสู่ระบบก่อนใช้งาน",
        )

    try:
        result = await db.execute(select(User).where(User.id == session_id))
        user_obj = result.scalar_one_or_none()
    except Exception:
        user_obj = None

    if not user_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session ไม่ถูกต้องหรือหมดอายุ",
        )

    role_val = getattr(user_obj, "role", "")
    role_str = str(role_val.value if hasattr(role_val, "value") else role_val)
    if "ADMIN" not in role_str and "SUPERADMIN" not in role_str:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ไม่มีสิทธิ์เข้าถึงส่วนผู้ดูแลระบบ",
        )

    return user_obj


# ------------------------------------------------------------------------------
# 🚀 APIRouter Setup
# ------------------------------------------------------------------------------
router = APIRouter(prefix="/admin", tags=["Admin Portal"])
templates = Jinja2Templates(directory="app/templates")

# In-memory token storage สำหรับล็อกอิน 2 ขั้นตอน (Step 1 -> Step 2)
temp_login_tokens: Dict[str, Dict[str, Any]] = {}

# ------------------------------------------------------------------------------
# 🌐 Route Endpoints
# ------------------------------------------------------------------------------


# [ฟังก์ชันที่ 5] Redirect เส้นทางหลัก /admin ไปยัง Dashboard หรือ Login
@router.get("", response_class=RedirectResponse, include_in_schema=False)
@router.get("/", response_class=RedirectResponse, include_in_schema=False)
async def admin_root_redirect(request: Request):
    if request.cookies.get("session"):
        return RedirectResponse(
            url="/admin/dashboard", status_code=status.HTTP_302_FOUND
        )
    return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)


# [ฟังก์ชันที่ 6] แสดงหน้าเข้าสู่ระบบ Admin Portal (Login HTML)
@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse(request=request, name="admin/login.html")


# [ฟังก์ชันที่ 7] API Step 1 - ตรวจสอบ Username, Password และสร้าง QR Code สแกนผูกครั้งแรก
@router.post("/api/login-step1")
async def login_step1(
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
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

    role_val = getattr(user_obj, "role", "")
    role_str = str(role_val.value if hasattr(role_val, "value") else role_val)
    if "ADMIN" not in role_str and "SUPERADMIN" not in role_str:
        raise HTTPException(
            status_code=403, detail="บัญชีนี้ไม่มีสิทธิ์เข้าใช้งานระบบผู้ดูแล"
        )

    existing_secret = getattr(user_obj, "totp_secret", None)
    is_first_time = not bool(existing_secret)

    totp_secret = pyotp.random_base32() if is_first_time else existing_secret
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user_obj.username, issuer_name="DLD-MFAcenter (Admin)"
    )
    qr_code_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(provisioning_uri)}"

    temp_token = str(uuid.uuid4())
    temp_login_tokens[temp_token] = {
        "user_id": str(user_obj.id),
        "username": user_obj.username,
        "totp_secret": totp_secret,
        "is_first_time": is_first_time,
        "created_at": datetime.utcnow(),
    }

    return {
        "success": True,
        "temp_token": temp_token,
        "is_first_time": is_first_time,
        "totp_secret": totp_secret if is_first_time else None,
        "qr_code_url": qr_code_url if is_first_time else None,
    }


# [ฟังก์ชันที่ 8] API Step 2 - ยืนยันรหัส OTP 6 หลัก และออก Cookie Session
@router.post("/api/login-step2")
async def login_step2(
    response: Response,
    temp_token: str = Form(...),
    totp_code: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    token_data = temp_login_tokens.get(temp_token)
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

    del temp_login_tokens[temp_token]

    response.set_cookie(
        key="session",
        value=token_data["user_id"],
        httponly=True,
        samesite="lax",
        path="/",
    )
    return {"success": True, "redirect_url": "/admin/dashboard"}


# [ฟังก์ชันที่ 9] API ออกจากระบบ (Logout) และล้าง Cookie
@router.get("/logout", response_class=RedirectResponse)
async def admin_logout(response: Response):
    res = RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)
    res.delete_cookie(key="session", path="/")
    return res


# [ฟังก์ชันที่ 10] แสดงหน้า Admin Dashboard (คุ้มครองด้วยการตรวจเช็ก Session Cookie)
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard_page(request: Request, db: AsyncSession = Depends(get_db)):
    session_id = request.cookies.get("session")
    if not session_id:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_302_FOUND)

    try:
        result = await db.execute(select(User).where(User.id == session_id))
        user_obj = result.scalar_one_or_none()
    except Exception:
        user_obj = None

    if not user_obj:
        response = RedirectResponse(
            url="/admin/login", status_code=status.HTTP_302_FOUND
        )
        response.delete_cookie(key="session", path="/")
        return response

    role_val = getattr(user_obj, "role", "")
    role_str = str(role_val.value if hasattr(role_val, "value") else role_val)
    if "ADMIN" not in role_str and "SUPERADMIN" not in role_str:
        response = RedirectResponse(
            url="/admin/login", status_code=status.HTTP_302_FOUND
        )
        response.delete_cookie(key="session", path="/")
        return response

    return templates.TemplateResponse(request=request, name="admin/dashboard.html")


# [ฟังก์ชันที่ 11] API ดึงข้อมูลสถิติภาพรวม (Summary Cards)
@router.get("/api/metrics")
async def get_admin_metrics(
    db: AsyncSession = Depends(get_db), current_user=Depends(get_current_admin)
):
    user_info = extract_user_info(current_user)
    role = user_info["role"]
    app_id = user_info["app_id"]

    if "SUPERADMIN" in role:
        app_count = (
            await db.execute(select(func.count(TargetApplication.id)))
        ).scalar() or 0
        user_count = (await db.execute(select(func.count(User.id)))).scalar() or 0
        log_count = (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0
        app_name = "ส่วนกลาง (ทุกระบบงาน)"
    else:
        app_count = 1 if app_id else 0
        user_count = (
            await db.execute(select(func.count(User.id)).where(User.app_id == app_id))
        ).scalar() or 0
        log_count = (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0
        app_obj = (
            await db.execute(
                select(TargetApplication).where(TargetApplication.id == app_id)
            )
        ).scalar_one_or_none()
        app_name = app_obj.app_name if app_obj else "ไม่ระบุระบบงาน"

    return {
        "username": user_info["username"],
        "role": role,
        "app_name": app_name,
        "total_applications": app_count,
        "total_users": user_count,
        "total_audit_logs": log_count,
        "must_change_password": False,
    }


# [ฟังก์ชันที่ 12] API ดึงข้อมูลสถิติกราฟ Visual Analytics (กราฟแนวโน้ม และ กราฟสัดส่วนผู้ใช้รายระบบ)
@router.get("/api/chart-data")
async def get_chart_data(
    days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    user_info = extract_user_info(current_user)
    role = user_info["role"]
    app_id = user_info["app_id"]

    today = datetime.utcnow().date()
    start_date = today - timedelta(days=days - 1)

    daily_query = select(
        func.date(AuditLog.timestamp).label("log_date"),
        func.count(AuditLog.id).label("count"),
    ).where(AuditLog.timestamp >= start_date)

    daily_query = daily_query.where(
        func.lower(func.cast(AuditLog.action, String)).like("%login%")
        | func.lower(func.cast(AuditLog.action, String)).like("%success%")
        | func.lower(func.cast(AuditLog.action, String)).like("%verified%")
    )

    if "SUPERADMIN" not in role and app_id and hasattr(AuditLog, "app_id"):
        daily_query = daily_query.where(AuditLog.app_id == app_id)

    daily_query = daily_query.group_by(func.date(AuditLog.timestamp)).order_by(
        "log_date"
    )
    daily_result = await db.execute(daily_query)
    daily_map = {str(row[0]): row[1] for row in daily_result.all()}

    dates = [str(start_date + timedelta(days=i)) for i in range(days)]
    daily_counts = [daily_map.get(d, 0) for d in dates]

    user_app_query = select(
        TargetApplication.app_name, func.count(User.id).label("count")
    ).outerjoin(User, TargetApplication.id == User.app_id)

    if "SUPERADMIN" not in role and app_id:
        user_app_query = user_app_query.where(TargetApplication.id == app_id)

    user_app_query = user_app_query.group_by(TargetApplication.app_name)
    user_app_result = await db.execute(user_app_query)
    users_by_app = {row[0] or "ไม่มีระบบงาน": row[1] for row in user_app_result.all()}

    if "SUPERADMIN" in role:
        unassigned_res = await db.execute(
            select(func.count(User.id)).where(User.app_id.is_(None))
        )
        unassigned_count = unassigned_res.scalar() or 0
        if unassigned_count > 0:
            users_by_app["Superadmin / ส่วนกลาง"] = unassigned_count

    return {
        "users_by_app": users_by_app,
        "daily_trends": {"labels": dates, "counts": daily_counts},
    }


# [ฟังก์ชันที่ 13] API ดึงรายชื่อผู้ใช้งานทั้งหมด
@router.get("/api/users")
async def get_users_list(
    db: AsyncSession = Depends(get_db), current_user=Depends(get_current_admin)
):
    user_info = extract_user_info(current_user)
    role = user_info["role"]
    app_id = user_info["app_id"]

    stmt = select(User, TargetApplication.app_name).outerjoin(
        TargetApplication, User.app_id == TargetApplication.id
    )
    if "SUPERADMIN" not in role and app_id:
        stmt = stmt.where(User.app_id == app_id)

    result = await db.execute(stmt)
    user_list = []
    for u, app_name in result.all():
        role_str = str(u.role.value if hasattr(u.role, "value") else u.role)
        user_list.append(
            {
                "id": str(u.id),
                "username": u.username,
                "role": role_str,
                "app_id": str(u.app_id) if u.app_id else None,
                "app_name": app_name
                or ("ส่วนกลาง" if "SUPERADMIN" in role_str else "ไม่ระบุ"),
                "is_mfa_enrolled": bool(
                    getattr(u, "totp_secret", None)
                    or getattr(u, "is_mfa_enrolled", False)
                ),
                "must_change_password": getattr(u, "must_change_password", False),
            }
        )
    return user_list


# [ฟังก์ชันที่ 14] API ล้างค่า MFA (Reset TOTP Secret) ของผู้ใช้
@router.post("/api/users/{user_id}/reset-mfa")
async def reset_user_mfa(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    res = await db.execute(select(User).where(User.id == user_id))
    user_obj = res.scalar_one_or_none()
    if not user_obj:
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้งาน")

    user_obj.totp_secret = None
    if hasattr(user_obj, "is_mfa_enrolled"):
        user_obj.is_mfa_enrolled = False

    await db.commit()
    return {"message": f"Reset MFA สำหรับผู้ใช้ '{user_obj.username}' เรียบร้อยแล้ว"}


# [ฟังก์ชันที่ 15] API ดึงรายชื่อระบบงานปลายทาง (Target Applications)
@router.get("/api/apps")
async def get_apps_list(
    db: AsyncSession = Depends(get_db), current_user=Depends(get_current_admin)
):
    res = await db.execute(select(TargetApplication))
    apps = res.scalars().all()
    return [
        {
            "id": str(app.id),
            "app_name": app.app_name,
            "public_domain": app.public_domain,
            "backend_target_url": getattr(
                app, "backend_target_url", getattr(app, "backend_url", "-")
            ),
            "enable_mfa": getattr(app, "enable_mfa", True),
            "is_bypass_enabled": getattr(app, "is_bypass_enabled", False),
        }
        for app in apps
    ]


# [ฟังก์ชันที่ 16] API ลงทะเบียนระบบงานใหม่
@router.post("/api/apps")
async def create_app(
    app_name: str = Form(...),
    public_domain: str = Form(...),
    backend_target_url: str = Form(...),
    enable_mfa: bool = Form(True),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    user_info = extract_user_info(current_user)
    if "SUPERADMIN" not in user_info["role"]:
        raise HTTPException(status_code=403, detail="สิทธิ์ไม่เพียงพอ")

    app_kwargs = {
        "app_name": app_name,
        "public_domain": public_domain,
        "enable_mfa": enable_mfa,
    }
    if hasattr(TargetApplication, "backend_target_url"):
        app_kwargs["backend_target_url"] = backend_target_url
    elif hasattr(TargetApplication, "backend_url"):
        app_kwargs["backend_url"] = backend_target_url

    new_app = TargetApplication(**app_kwargs)
    db.add(new_app)
    await db.commit()
    return {"message": f"ลงทะเบียนระบบงาน '{app_name}' สำเร็จ"}


# [ฟังก์ชันที่ 17] API สลับสวิตช์ Emergency MFA Bypass
@router.post("/api/apps/{app_id}/toggle-bypass")
async def toggle_app_bypass(
    app_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    user_info = extract_user_info(current_user)
    if "SUPERADMIN" not in user_info["role"]:
        raise HTTPException(status_code=403, detail="สิทธิ์ไม่เพียงพอ")

    res = await db.execute(
        select(TargetApplication).where(TargetApplication.id == app_id)
    )
    app_obj = res.scalar_one_or_none()
    if not app_obj:
        raise HTTPException(status_code=404, detail="ไม่พบระบบงาน")

    app_obj.is_bypass_enabled = not getattr(app_obj, "is_bypass_enabled", False)
    await db.commit()
    status_str = (
        "เปิดใช้งาน (Bypass)" if app_obj.is_bypass_enabled else "ปิดใช้งาน (บังคับ MFA)"
    )
    return {
        "message": f"เปลี่ยนสถานะ MFA Bypass ของระบบ '{app_obj.app_name}' เป็น {status_str}"
    }


# [ฟังก์ชันที่ 18] API ดึงบันทึกเหตุการณ์ความปลอดภัย (Audit Logs)
@router.get("/api/audit-logs")
async def get_audit_logs(
    db: AsyncSession = Depends(get_db), current_user=Depends(get_current_admin)
):
    res = await db.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200)
    )
    logs = res.scalars().all()
    return [
        {
            "id": str(log.id),
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "app_domain": getattr(log, "app_domain", "-"),
            "client_ip": getattr(log, "client_ip", "-"),
            "username": getattr(log, "username", "-"),
            "action": str(
                log.action.value if hasattr(log.action, "value") else log.action
            ),
        }
        for log in logs
    ]


# [ฟังก์ชันที่ 19] API เพิ่มผู้ดูแลระบบประจำแอป (App Admin)
@router.post("/api/create-admin")
async def create_app_admin(
    app_id: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    user_info = extract_user_info(current_user)
    if "SUPERADMIN" not in user_info["role"]:
        raise HTTPException(status_code=403, detail="สิทธิ์ไม่เพียงพอ")

    existing_res = await db.execute(select(User).where(User.username == username))
    if existing_res.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username นี้มีอยู่ในระบบแล้ว")

    hashed_pwd = get_password_hash(password)
    admin_role = getattr(UserRole, "APP_ADMIN", "APP_ADMIN")

    user_kwargs = {"username": username, "role": admin_role, "app_id": app_id}
    if hasattr(User, "password_hash"):
        user_kwargs["password_hash"] = hashed_pwd
    elif hasattr(User, "hashed_password"):
        user_kwargs["hashed_password"] = hashed_pwd
    elif hasattr(User, "password"):
        user_kwargs["password"] = hashed_pwd

    if hasattr(User, "must_change_password"):
        user_kwargs["must_change_password"] = True

    new_admin = User(**user_kwargs)
    db.add(new_admin)
    await db.commit()
    return {"message": f"เพิ่ม App Admin '{username}' สำเร็จ"}


# [ฟังก์ชันที่ 20] API เปลี่ยนรหัสผ่าน Admin
@router.post("/api/change-password")
async def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
):
    if new_password != confirm_password:
        raise HTTPException(
            status_code=400, detail="รหัสผ่านใหม่และการยืนยันรหัสผ่านไม่ตรงกัน"
        )

    user_info = extract_user_info(current_user)
    user_id = user_info["id"]

    result = await db.execute(select(User).where(User.id == user_id))
    user_obj = result.scalar_one_or_none()
    if not user_obj:
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้งาน")

    current_hash = (
        getattr(user_obj, "password_hash", None)
        or getattr(user_obj, "hashed_password", None)
        or getattr(user_obj, "password", None)
    )

    if not current_hash or not verify_password(old_password, current_hash):
        raise HTTPException(status_code=400, detail="รหัสผ่านเดิมไม่ถูกต้อง")

    new_hash = get_password_hash(new_password)
    if hasattr(user_obj, "password_hash"):
        user_obj.password_hash = new_hash
    elif hasattr(user_obj, "hashed_password"):
        user_obj.hashed_password = new_hash
    elif hasattr(user_obj, "password"):
        user_obj.password = new_hash

    if hasattr(user_obj, "must_change_password"):
        user_obj.must_change_password = False

    await db.commit()
    return {"message": "เปลี่ยนรหัสผ่านเรียบร้อยแล้ว"}

# app/routers/admin.py
from fastapi import APIRouter, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_
from sqlalchemy.orm import selectinload
import uuid
import secrets

from app.core.database import get_db
from app.core.redis import get_redis
from app.core.config import settings
from app.core.security import verify_password, verify_totp_code, hash_password
from app.models.schemas import TargetApplication, AuditLog, User, UserRole
from app.proxy.proxy_router import audit_logger

from pathlib import Path
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(prefix="/admin", tags=["Admin Dashboard"])
templates = Jinja2Templates(directory="app/templates")

ADMIN_SESSION_COOKIE = "dld_admin_session"

# Helper Function ตรวจสอบ Session การล็อกอินของ Admin
async def get_current_admin(request: Request, db: AsyncSession = Depends(get_db)):
    session_id = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not session_id:
        return None

    redis = get_redis()
    session_data = await redis.hgetall(f"admin_session:{session_id}")
    if not session_data:
        return None

    role = session_data.get("role")
    if role not in [UserRole.SUPERADMIN.value, UserRole.APP_ADMIN.value]:
        return None

    app_name = "ทุกระบบส่วนกลาง" if role == UserRole.SUPERADMIN.value else "ไม่ระบุระบบ"
    app_id = session_data.get("app_id")
    if app_id:
        app_obj = await db.scalar(select(TargetApplication).where(TargetApplication.id == uuid.UUID(app_id)))
        if app_obj:
            app_name = app_obj.app_name

    session_data["app_name"] = app_name
    return session_data

# =========================================================================
# 1. หน้าล็อกอินและกระบวนการเข้าสู่ระบบ/ออกจากระบบของ Admin
# =========================================================================
@router.get("/login", response_class=HTMLResponse)
async def render_admin_login(request: Request):
    return templates.TemplateResponse(request=request, name="admin/login.html", context={})

@router.post("/login")
async def process_admin_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp_code: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.username == username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")

    if not user or user.role == UserRole.USER or not verify_password(password, user.password_hash):
        return JSONResponse({"status": "failed", "message": "Username หรือ Password ไม่ถูกต้อง"}, status_code=401)

    if not user.totp_secret or not verify_totp_code(user.totp_secret, totp_code):
        return JSONResponse({"status": "failed", "message": "รหัส TOTP 6 หลักไม่ถูกต้อง"}, status_code=401)

    redis = get_redis()
    session_id = secrets.token_hex(32)
    session_key = f"admin_session:{session_id}"
    
    await redis.hset(session_key, mapping={
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role.value,
        "app_id": str(user.app_id) if user.app_id else "",
        "must_change_password": "1" if user.must_change_password else "0"
    })
    await redis.expire(session_key, settings.SESSION_TTL_SECONDS)

    # บันทึก Audit Log การเข้าสู่ระบบ Admin
    await audit_logger(
        db=db,
        app_id=user.app_id,
        app_domain="mfa.dld.go.th",
        client_ip=client_ip,
        username=user.username,
        action=f"ADMIN_LOGIN ({user.role.value})",
        user_agent=user_agent
    )

    response = JSONResponse({
        "status": "success",
        "redirect_url": "/admin",
        "must_change_password": user.must_change_password
    })
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.SESSION_TTL_SECONDS
    )
    return response

@router.get("/logout")
async def admin_logout(request: Request):
    session_id = request.cookies.get(ADMIN_SESSION_COOKIE)
    if session_id:
        redis = get_redis()
        await redis.delete(f"admin_session:{session_id}")
    response = RedirectResponse(url="/admin/login", status_code=303)
    response.delete_cookie(ADMIN_SESSION_COOKIE)
    return response

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def render_admin_dashboard(request: Request, current_user=Depends(get_current_admin)):
    if not current_user:
        return RedirectResponse(url="/admin/login", status_code=303)
    return templates.TemplateResponse(request=request, name="admin/dashboard.html", context={})

# =========================================================================
# 2. API สถิติภาพรวม Dashboard Metrics
# =========================================================================
@router.get("/api/metrics")
async def get_dashboard_metrics(db: AsyncSession = Depends(get_db), current_user=Depends(get_current_admin)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    is_super = current_user.get("role") == UserRole.SUPERADMIN.value
    user_app_id = current_user.get("app_id")
    admin_username = current_user.get("username")

    if is_super:
        total_apps = await db.scalar(select(func.count(TargetApplication.id)))
        total_users = await db.scalar(select(func.count(User.id)))
        total_logs = await db.scalar(select(func.count(AuditLog.id)))
    else:
        total_apps = 1 if user_app_id else 0
        total_users = await db.scalar(select(func.count(User.id)).where(User.app_id == uuid.UUID(user_app_id))) if user_app_id else 0
        
        app_domain = await db.scalar(select(TargetApplication.public_domain).where(TargetApplication.id == uuid.UUID(user_app_id))) if user_app_id else ""
        log_stmt = select(func.count(AuditLog.id)).where(
            or_(
                AuditLog.target_app_id == uuid.UUID(user_app_id) if user_app_id else False,
                AuditLog.app_domain == app_domain if app_domain else False,
                AuditLog.username == admin_username
            )
        )
        total_logs = await db.scalar(log_stmt)

    return {
        "total_applications": total_apps or 0,
        "total_users": total_users or 0,
        "total_audit_logs": total_logs or 0,
        "role": current_user.get("role"),
        "username": current_user.get("username"),
        "app_name": current_user.get("app_name"),
        "must_change_password": current_user.get("must_change_password") == "1"
    }

# =========================================================================
# 3. API จัดการผู้ใช้งาน (Users & Reset MFA)
# =========================================================================
@router.get("/api/users")
async def list_users(
    app_id: str | None = None,
    search: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    is_super = current_user.get("role") == UserRole.SUPERADMIN.value
    user_app_id = current_user.get("app_id")

    stmt = select(User).options(selectinload(User.application))

    if not is_super and user_app_id:
        stmt = stmt.where(User.app_id == uuid.UUID(user_app_id))
    elif is_super and app_id:
        stmt = stmt.where(User.app_id == uuid.UUID(app_id))

    if search and search.strip():
        stmt = stmt.where(User.username.ilike(f"%{search.strip()}%"))
    
    stmt = stmt.order_by(User.created_at.desc())
    result = await db.execute(stmt)
    users = result.scalars().all()

    redis = get_redis()
    user_list = []
    for u in users:
        is_enrolled = await redis.get(f"totp_enrolled:{u.username}")
        
        if u.role == UserRole.SUPERADMIN:
            app_display_name = "ทุกระบบส่วนกลาง"
        elif u.application:
            app_display_name = u.application.app_name
        else:
            app_display_name = "ไม่ระบุระบบ"

        user_list.append({
            "id": str(u.id),
            "username": u.username,
            "role": u.role.value,
            "app_id": str(u.app_id) if u.app_id else None,
            "app_name": app_display_name,
            "is_mfa_enrolled": bool(is_enrolled or u.totp_secret),
            "must_change_password": u.must_change_password,
            "created_at": u.created_at.isoformat() if u.created_at else None
        })

    return user_list

# =========================================================================
# 4. API จัดการระบบงาน (Target Applications) & Emergency MFA Bypass
# =========================================================================
@router.get("/api/apps")
async def list_target_applications(db: AsyncSession = Depends(get_db), current_user=Depends(get_current_admin)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    stmt = select(TargetApplication).order_by(TargetApplication.created_at.desc())
    result = await db.execute(stmt)
    apps = result.scalars().all()

    app_list = []
    for app in apps:
        app_list.append({
            "id": str(app.id),
            "app_name": app.app_name,
            "public_domain": app.public_domain,
            "backend_target_url": app.backend_target_url,
            "enable_mfa": app.enable_mfa,
            "is_bypass_enabled": bool(app.is_bypass_enabled)  # ส่งสถานะ Bypass ล่าสุด
        })

    return app_list

@router.post("/api/apps")
async def create_target_application(
    request: Request,
    app_name: str = Form(...),
    public_domain: str = Form(...),
    backend_target_url: str = Form(...),
    enable_mfa: bool = Form(True),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user or current_user.get("role") != UserRole.SUPERADMIN.value:
        raise HTTPException(status_code=403, detail="เฉพาะ Superadmin เท่านั้นที่เพิ่มระบบงานได้")

    existing = await db.scalar(select(TargetApplication).where(TargetApplication.public_domain == public_domain.strip()))
    if existing:
        raise HTTPException(status_code=400, detail="Domain หน้าบ้านนี้ถูกใช้งานในระบบแล้ว")

    new_app = TargetApplication(
        id=uuid.uuid4(),
        app_name=app_name.strip(),
        public_domain=public_domain.strip(),
        backend_target_url=backend_target_url.strip(),
        enable_mfa=enable_mfa,
        is_bypass_enabled=False
    )
    db.add(new_app)
    await db.commit()

    # บันทึก Audit Log
    client_ip = request.client.host if request.client else "127.0.0.1"
    await audit_logger(
        db=db,
        app_id=new_app.id,
        app_domain=new_app.public_domain,
        client_ip=client_ip,
        username=current_user.get("username"),
        action=f"CREATE_APPLICATION ({new_app.app_name})",
        user_agent=request.headers.get("user-agent", "")
    )

    return {"status": "success", "message": f"เพิ่มระบบงาน {new_app.app_name} สำเร็จ"}

# ⚡ API สลับสถานะ Emergency MFA Bypass (Superadmin เท่านั้น)
@router.post("/api/apps/{app_id}/toggle-bypass")
async def toggle_app_bypass(
    app_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user or current_user.get("role") != UserRole.SUPERADMIN.value:
        raise HTTPException(status_code=403, detail="เฉพาะ Superadmin เท่านั้นที่มีสิทธิ์เปิด/ปิด Bypass")

    target_uuid = uuid.UUID(app_id)
    app = await db.scalar(select(TargetApplication).where(TargetApplication.id == target_uuid))
    if not app:
        raise HTTPException(status_code=404, detail="ไม่พบระบบงาน")

    # สลับสถานะ True <-> False
    app.is_bypass_enabled = not app.is_bypass_enabled
    await db.commit()

    # บันทึก Audit Log
    client_ip = request.client.host if request.client else "127.0.0.1"
    action_name = "ENABLE_EMERGENCY_BYPASS" if app.is_bypass_enabled else "DISABLE_EMERGENCY_BYPASS"
    await audit_logger(
        db=db,
        app_id=app.id,
        app_domain=app.public_domain,
        client_ip=client_ip,
        username=current_user.get("username"),
        action=f"{action_name} ({app.app_name})",
        user_agent=request.headers.get("user-agent", "")
    )

    status_msg = "เปิดใช้งาน MFA Bypass กรณีฉุกเฉิน" if app.is_bypass_enabled else "ปิดใช้งาน MFA Bypass (กลับสู่โหมดปกติ)"
    return {
        "status": "success",
        "message": f"{status_msg} สำหรับ {app.app_name} เรียบร้อยแล้ว",
        "is_bypass_enabled": app.is_bypass_enabled
    }

# =========================================================================
# 5. API จัดการอื่นๆ (สร้าง Admin, เปลี่ยนรหัสผ่าน, Reset MFA, Audit Logs)
# =========================================================================
@router.post("/api/create-admin")
async def create_app_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    app_id: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user or current_user.get("role") != UserRole.SUPERADMIN.value:
        raise HTTPException(status_code=403, detail="เฉพาะ Superadmin เท่านั้นที่สร้าง Admin ได้")

    existing = await db.scalar(select(User).where(User.username == username.strip()))
    if existing:
        raise HTTPException(status_code=400, detail="ชื่อผู้ใช้งานนี้มีอยู่ในระบบแล้ว")

    target_app_uuid = uuid.UUID(app_id)
    new_admin = User(
        username=username.strip(),
        password_hash=hash_password(password),
        role=UserRole.APP_ADMIN,
        app_id=target_app_uuid,
        totp_secret="JBSWY3DPEHPK3PXP",
        must_change_password=True
    )
    db.add(new_admin)
    await db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await audit_logger(
        db=db,
        app_id=target_app_uuid,
        app_domain="mfa.dld.go.th",
        client_ip=client_ip,
        username=current_user.get("username"),
        action=f"CREATE_APP_ADMIN ({username.strip()})",
        user_agent=request.headers.get("user-agent", "")
    )

    return {"status": "success", "message": f"สร้าง Admin {username} สำเร็จ"}

@router.post("/api/change-password")
async def change_admin_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="รหัสผ่านใหม่และการยืนยันรหัสผ่านไม่ตรงกัน")

    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="รหัสผ่านใหม่ต้องมีความยาวอย่างน้อย 6 ตัวอักษร")

    user_id = current_user.get("user_id")
    user = await db.scalar(select(User).where(User.id == uuid.UUID(user_id)))

    if not user or not verify_password(old_password, user.password_hash):
        raise HTTPException(status_code=400, detail="รหัสผ่านเดิมไม่ถูกต้อง")

    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    await db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await audit_logger(
        db=db,
        app_id=user.app_id,
        app_domain="mfa.dld.go.th",
        client_ip=client_ip,
        username=user.username,
        action="CHANGE_PASSWORD",
        user_agent=request.headers.get("user-agent", "")
    )

    return {"status": "success", "message": "เปลี่ยนรหัสผ่านสำเร็จแล้ว"}

@router.post("/api/users/{user_id}/reset-mfa")
async def reset_user_mfa(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    is_super = current_user.get("role") == UserRole.SUPERADMIN.value
    admin_app_id = current_user.get("app_id")

    user = await db.scalar(select(User).where(User.id == uuid.UUID(user_id)))
    if not user:
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้งาน")

    if not is_super and str(user.app_id) != admin_app_id:
        raise HTTPException(status_code=403, detail="ไม่มีสิทธิ์จัดการผู้ใช้งานในระบบนี้")

    redis = get_redis()
    await redis.delete(f"totp_enrolled:{user.username}")
    user.totp_secret = None
    await db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await audit_logger(
        db=db,
        app_id=user.app_id,
        app_domain="mfa.dld.go.th",
        client_ip=client_ip,
        username=current_user.get("username"),
        action=f"RESET_MFA ({user.username})",
        user_agent=request.headers.get("user-agent", "")
    )

    return {"status": "success", "message": f"Reset MFA ให้ {user.username} สำเร็จ"}

@router.get("/api/audit-logs")
async def get_recent_audit_logs(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    is_super = current_user.get("role") == UserRole.SUPERADMIN.value
    user_app_id = current_user.get("app_id")
    admin_username = current_user.get("username")

    stmt = select(AuditLog)

    if not is_super:
        filters = []
        if user_app_id:
            filters.append(AuditLog.target_app_id == uuid.UUID(user_app_id))
            app_domain = await db.scalar(
                select(TargetApplication.public_domain).where(TargetApplication.id == uuid.UUID(user_app_id))
            )
            if app_domain:
                filters.append(AuditLog.app_domain == app_domain)

        if admin_username:
            filters.append(AuditLog.username == admin_username)

        if filters:
            stmt = stmt.where(or_(*filters))

    stmt = stmt.order_by(desc(AuditLog.timestamp)).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()
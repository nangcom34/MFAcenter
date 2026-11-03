# app/models/schemas.py
import uuid
from datetime import datetime
import enum
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum as SQLEnum, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base

class UserRole(str, enum.Enum):
    SUPERADMIN = "SUPERADMIN"
    APP_ADMIN = "APP_ADMIN"
    USER = "USER"

class AuditAction(str, enum.Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    TOTP_VERIFY_SUCCESS = "TOTP_VERIFY_SUCCESS"
    TOTP_VERIFY_FAILED = "TOTP_VERIFY_FAILED"
    EMERGENCY_MFA_BYPASS = "EMERGENCY_MFA_BYPASS"
    ADMIN_LOGIN = "ADMIN_LOGIN"
    RESET_MFA = "RESET_MFA"
    CHANGE_PASSWORD = "CHANGE_PASSWORD"
    CREATE_APP_ADMIN = "CREATE_APP_ADMIN"
    CREATE_APPLICATION = "CREATE_APPLICATION"
    ENABLE_EMERGENCY_BYPASS = "ENABLE_EMERGENCY_BYPASS"
    DISABLE_EMERGENCY_BYPASS = "DISABLE_EMERGENCY_BYPASS"

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.USER, nullable=False)
    app_id = Column(UUID(as_uuid=True), ForeignKey("target_applications.id", ondelete="SET NULL"), nullable=True)
    totp_secret = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    must_change_password = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    application = relationship("TargetApplication", backref="users")

class TargetApplication(Base):
    __tablename__ = "target_applications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    app_name = Column(String(100), nullable=False)
    public_domain = Column(String(150), unique=True, nullable=False, index=True)
    backend_target_url = Column(String(255), nullable=False)
    legacy_login_path = Column(String(255), default="/login", nullable=True)  # ✅ เพิ่มคอลัมน์ป้องกัน AttributeError
    enable_mfa = Column(Boolean, default=True)
    is_bypass_enabled = Column(Boolean, default=False)                       # ✅ เพิ่มคอลัมน์เก็บสถานะ Bypass
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_app_id = Column(UUID(as_uuid=True), ForeignKey("target_applications.id", ondelete="CASCADE"), nullable=True)
    app_domain = Column(String(150), nullable=False, index=True)
    client_ip = Column(String(50), nullable=False)
    username = Column(String(100), nullable=True)
    action = Column(String(255), nullable=False)  # ✅ ปรับจาก String(100)/VARCHAR(50) เป็น String(255)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
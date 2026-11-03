import pyotp
import qrcode
import io
import base64
import bcrypt
import secrets

def hash_password(password: str) -> str:
    """ เข้ารหัสรหัสผ่านด้วย bcrypt โดยตรง """
    pwd_bytes = password.encode('utf-8')[:72]  # bcrypt รองรับสูงสุด 72 bytes
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """ ตรวจสอบรหัสผ่านผ่าน bcrypt """
    try:
        pwd_bytes = plain_password.encode('utf-8')[:72]
        hash_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def generate_qr_code_base64(secret: str, username: str, issuer: str = "DLD MFAcenter") -> str:
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def generate_break_glass_code() -> str:
    return f"DLD-EMERGENCY-{secrets.token_hex(4).upper()}"

def generate_qr_code_base64(secret: str, username: str, issuer: str = "DLD MFAcenter") -> str:
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")
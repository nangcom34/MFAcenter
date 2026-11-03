from sqlalchemy.ext.asyncio import AsyncSession
from app.core.redis import get_redis

class BreakGlassService:
    """
    บริการจัดการและตรวจสอบรหัสผ่านฉุกเฉิน (Master Break-Glass Code)
    เพื่อใช้ทะลุผ่าน MFA ในกรณีระบบยืนยันตัวตนมีปัญหาหรือเหตุฉุกเฉิน
    """

    # รหัสฉุกเฉินส่วนกลาง (Master Emergency Codes)
    MASTER_BREAK_GLASS_CODES = [
        "DLD-EMERGENCY-9999",
        "DLD-EMERGENCY-8888"
    ]

    @classmethod
    async def validate_and_consume_token(cls, db: AsyncSession, app_id: str, code: str) -> bool:
        """
        ตรวจสอบความถูกต้องของรหัสฉุกเฉิน และลบล้างรหัสกรณีเป็น One-Time Token
        """
        if not code:
            return False

        cleaned_code = code.strip().upper()

        # 1. ตรวจสอบกับ Master Codes ส่วนกลาง
        if cleaned_code in cls.MASTER_BREAK_GLASS_CODES:
            return True

        # 2. ตรวจสอบกับ Dynamic One-Time Token ที่สร้างใน Redis (ถ้ามี)
        redis = get_redis()
        redis_key = f"break_glass:{app_id}:{cleaned_code}"
        is_valid = await redis.get(redis_key)

        if is_valid:
            # ใช้แล้วลบทันที (One-Time Consumption)
            await redis.delete(redis_key)
            return True

        return False
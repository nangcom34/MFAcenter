import time
import secrets  
from redis.asyncio import Redis
from fastapi import HTTPException, status
from app.core.config import settings

class AntiBruteForceLimiter:
    def __init__(self, redis: Redis):
        self.redis = redis

    async def check_and_increment(self, client_ip: str, username: str) -> tuple[bool, int]:
        """
        ตรวจสอบ Rate Limit และ Brute Force
        คืนค่า (is_blocked, remaining_seconds_if_blocked)
        """
        current_time = int(time.time())
        ip_key = f"rate_limit:ip:{client_ip}"
        user_key = f"rate_limit:user:{username}"
        ip_lock_key = f"lockout:ip:{client_ip}"
        user_lock_key = f"lockout:user:{username}"

        # ตรวจสอบสภาวะการบล็อกใน Redis
        ip_ttl = await self.redis.ttl(ip_lock_key)
        if ip_ttl > 0:
            return True, ip_ttl

        user_ttl = await self.redis.ttl(user_lock_key)
        if user_ttl > 0:
            return True, user_ttl

        return False, 0

    async def record_failure(self, client_ip: str, username: str):
        """
        บันทึกความล้มเหลวโดยใช้ Sliding Window
        """
        current_time = int(time.time())
        window_start = current_time - settings.RATE_LIMIT_WINDOW_SECONDS

        for key_type, identifier in [("ip", client_ip), ("user", username)]:
            key = f"rate_limit:{key_type}:{identifier}"
            lock_key = f"lockout:{key_type}:{identifier}"

            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(key, 0, window_start)
                pipe.zadd(key, {f"{current_time}:{secrets.token_hex(2)}": current_time})
                pipe.zcard(key)
                pipe.expire(key, settings.RATE_LIMIT_WINDOW_SECONDS)
                results = await pipe.execute()

            failure_count = results[2]

            if failure_count >= settings.RATE_LIMIT_MAX_ATTEMPTS:
                await self.redis.set(lock_key, "LOCKED", ex=settings.RATE_LIMIT_LOCKOUT_SECONDS)

    async def reset_on_success(self, client_ip: str, username: str):
        """
        ลบสถิติล้มเหลวเมื่อล็อกอินสำเร็จ
        """
        await self.redis.delete(
            f"rate_limit:ip:{client_ip}",
            f"rate_limit:user:{username}"
        )
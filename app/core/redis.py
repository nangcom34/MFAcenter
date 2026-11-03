import redis.asyncio as aioredis
from app.core.config import settings

redis_client: aioredis.Redis = None

def get_redis() -> aioredis.Redis:
    """
    ดึง Redis Instance (Lazy Initialization เพื่อป้องกันการคืนค่า None)
    """
    global redis_client
    if redis_client is None:
        redis_client = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True
        )
    return redis_client

async def close_redis():
    global redis_client
    if redis_client is not None:
        await redis_client.close()
        redis_client = None
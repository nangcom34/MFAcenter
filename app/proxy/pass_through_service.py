# app/proxy/pass_through_service.py
import httpx
from app.models.schemas import TargetApplication

class LegacyPassThroughService:
    @staticmethod
    async def verify_legacy_credentials(app: TargetApplication, username: str, password: str) -> bool:
        """
        ตรวจสอบ Username/Password กับระบบหลังบ้านผ่าน Pass-through Auth
        พร้อมระบบป้องกัน Crash หากระบบหลังบ้านปิดหรือเชื่อมต่อไม่ได้
        """
        login_path = getattr(app, 'legacy_login_path', '/login') or '/login'
        target_login_url = f"{app.backend_target_url.rstrip('/')}/{login_path.lstrip('/')}"
        
        # กำหนดเวลาเชื่อมต่อสูงสุด 5 วินาที
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, limits=limits, verify=False) as client:
            try:
                resp = await client.post(
                    target_login_url,
                    data={"username": username, "password": password},
                    headers={"User-Agent": "DLD-MFAcenter-Proxy/1.0"}
                )
                return resp.status_code in [200, 302]
            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError) as e:
                print(f"[PASS-THROUGH CONNECT ERROR] ไม่สามารถเชื่อมต่อหลังบ้าน {target_login_url}: {str(e)}")
                return False
            except Exception as e:
                print(f"[PASS-THROUGH UNKNOWN ERROR] {str(e)}")
                return False
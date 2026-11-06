import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.routers import auth, admin

app = FastAPI(
    title="DLD-MFAcenter",
    description="Multi-Factor Authentication Proxy Gateway - Department of Livestock Development",
    version="1.0.0",
)

# Mount โฟลเดอร์ Static Files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory="app/templates")

# 🔑 ลงทะเบียน Routers
app.include_router(auth.router)
app.include_router(admin.router)


# [ฟังก์ชันที่ 1] Root Endpoint สำหรับแสดงหน้าเข้าสู่ระบบของผู้ใช้งานทั่วไป (User Login HTML)
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    try:
        return templates.TemplateResponse(request=request, name="auth/login.html")
    except Exception:
        return templates.TemplateResponse(request=request, name="login.html")


# [ฟังก์ชันที่ 2] Health Check Endpoint สำหรับตรวจสอบสถานะของ Container
@app.get("/health", tags=["Health Check"])
async def health_check():
    return {"status": "ok", "service": "DLD-MFAcenter"}

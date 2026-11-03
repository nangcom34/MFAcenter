# app/main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers import auth, admin
from app.proxy import proxy_router

app = FastAPI(title="DLD-MFAcenter Gateway")

# 1. ลงทะเบียน Auth และ Admin Routers ก่อนเป็นอันดับแรก
app.include_router(auth.router)
app.include_router(admin.router)

# 2. ลงทะเบียน Dynamic Proxy Router เป็นลำดับสุดท้าย
app.include_router(proxy_router.router)
from fastapi import APIRouter, Depends, HTTPException, Form
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.schemas import OnboardingRequest, OnboardingStatus

router = APIRouter(prefix="/portal", tags=["Public Portal & Onboarding"])

@router.get("/")
async def portal_home():
    return {"status": "online", "message": "DLD-MFAcenter Portal Service"}

@router.post("/onboard")
async def submit_onboarding_request(
    system_name: str = Form(...),
    system_url: str = Form(...),
    contact_person: str = Form(...),
    contact_email: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    request_entry = OnboardingRequest(
        system_name=system_name,
        system_url=system_url,
        contact_person=contact_person,
        contact_email=contact_email,
        status=OnboardingStatus.PENDING
    )
    db.add(request_entry)
    await db.commit()
    return {"status": "success", "message": "ส่งคำขอเชื่อมต่อระบบสำเร็จ"}
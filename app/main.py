from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.models import User
from app.schemas import UserResponse
from app.dependencies import get_current_user
from app.routers.auth import router as auth_router

app = FastAPI(title="Signup Signin JWT API")

# Create missing tables; existing tables ke columns update nahi karta.
Base.metadata.create_all(bind=engine)

app.include_router(auth_router)


@app.get("/")
def home():
    return {"message": "Authentication API is running"}


@app.get("/profile", response_model=UserResponse)
def profile(user: User = Depends(get_current_user)):
    return user
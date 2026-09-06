from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr
from typing import Optional
from sqlalchemy.orm import Session

from app.auth import create_access_token, decode_access_token, hash_password, verify_password
from app.database import SessionLocal, settings
from app.models import User


router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RegisterRequest(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthUserResponse(BaseModel):
    id: str
    email: str
    name: Optional[str]

    class Config:
        from_attributes = True


def set_auth_cookie(response: Response, user_id: str):
    token = create_access_token(user_id)

    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


def get_current_user(
    auth_token: Optional[str] = Cookie(default=None, alias=settings.AUTH_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> User:
    if not auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        user_id = decode_access_token(auth_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
        )

    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


@router.post("/register", response_model=AuthUserResponse, status_code=201)
def register(
    data: RegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    if len(data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters",
        )

    email = data.email.strip().lower()

    existing_user = db.query(User).filter(User.email == email).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        name=data.name,
        password_hash=hash_password(data.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    set_auth_cookie(response, user.id)

    return user


@router.post("/login", response_model=AuthUserResponse)
def login(
    data: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    email = data.email.strip().lower()

    user = db.query(User).filter(User.email == email).first()

    if not user or not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    set_auth_cookie(response, user.id)

    return user


@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        path="/",
    )


@router.get("/me", response_model=AuthUserResponse)
def me(
    current_user: User = Depends(get_current_user),
):
    return current_user

"""
User management endpoints.

Note: user registration and authentication are handled by /api/auth/*.
This router is reserved for future user-management features (profile update,
account deletion, etc.) that require authentication.
"""
from fastapi import APIRouter


router = APIRouter(prefix="/users", tags=["Users"])

# No unauthenticated endpoints are exposed here.
# See /api/auth/register for account creation and /api/auth/me for profile.

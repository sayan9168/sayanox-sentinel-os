"""
Authentication API Router
JWT-based login, token refresh, and user management
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from datetime import timedelta

from backend.models.schemas import Token, UserLogin, UserCreate, User as UserSchema
from backend.middleware.auth import (
    authenticate_user, create_access_token, create_refresh_token,
    decode_token, get_user_from_db, get_password_hash, USERS_DB,
    has_permission, TokenData
)
from backend.middleware.security import audit_logger

router = APIRouter()
security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Dependency to get current authenticated user from JWT token"""
    token = credentials.credentials
    token_data = decode_token(token)
    
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = get_user_from_db(token_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "id": user["id"]
    }


def require_role(required_role: str):
    """Dependency factory to require specific role"""
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if not has_permission(current_user["role"], required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )
        return current_user
    return role_checker


# Export for other modules
__all__ = ["get_current_user", "require_role"]


@router.post("/login", response_model=Token)
async def login(login_data: UserLogin):
    """
    Authenticate user and return JWT tokens
    Default credentials: admin/admin123 (admin role), viewer/viewer123 (viewer role)
    """
    user = authenticate_user(login_data.username, login_data.password)
    
    if not user:
        # Log failed login attempt
        audit_logger.log_event(
            event_type="AUTH_FAILURE",
            user=login_data.username,
            action="LOGIN_FAILED",
            details={"reason": "Invalid credentials"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"],
            "user_id": user["id"]
        },
        expires_delta=timedelta(minutes=60)
    )
    
    refresh_token = create_refresh_token(
        data={
            "sub": user["username"],
            "role": user["role"],
            "user_id": user["id"]
        }
    )
    
    # Log successful login
    audit_logger.log_event(
        event_type="AUTH_SUCCESS",
        user=user["username"],
        action="LOGIN_SUCCESS",
        details={"role": user["role"]}
    )
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    token_data = decode_token(refresh_token)
    
    if not token_data or token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = get_user_from_db(token_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    new_access_token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"],
            "user_id": user["id"]
        }
    )
    
    return Token(
        access_token=new_access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.get("/me", response_model=UserSchema)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return UserSchema(
        id=current_user["id"],
        username=current_user["username"],
        email=current_user["email"],
        role=current_user["role"],
        disabled=False
    )


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout user (client should discard tokens)"""
    audit_logger.log_event(
        event_type="AUTH_LOGOUT",
        user=current_user["username"],
        action="LOGOUT",
        details={}
    )
    
    return {"message": "Successfully logged out"}


@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_users():
    """List all users (admin only)"""
    users = []
    for username, user_data in USERS_DB.items():
        users.append({
            "id": user_data["id"],
            "username": user_data["username"],
            "email": user_data["email"],
            "role": user_data["role"],
            "disabled": user_data.get("disabled", False)
        })
    return {"users": users}

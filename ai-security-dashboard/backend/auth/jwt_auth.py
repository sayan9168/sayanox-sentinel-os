"""
JWT Authentication & RBAC Module
Implements OAuth2-compatible JWT authentication with role-based access control
"""

import os
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from functools import wraps
from fastapi import HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for REST API
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# RBAC Roles
class Role:
    ADMIN = "admin"
    VIEWER = "viewer"

# Permission mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: {
        "terminal_access", "process_kill", "firewall_edit", 
        "browser_control", "webhook_config", "metrics_read", 
        "threats_read", "skills_read", "audit_logs"
    },
    Role.VIEWER: {
        "metrics_read", "threats_read"
    }
}

# In-memory user store (replace with database in production)
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),  # Change in production!
        "role": Role.ADMIN,
        "full_name": "System Administrator",
        "email": "admin@security.local"
    },
    "viewer": {
        "username": "viewer",
        "hashed_password": pwd_context.hash("viewer123"),  # Change in production!
        "role": Role.VIEWER,
        "full_name": "Security Viewer",
        "email": "viewer@security.local"
    }
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user by username and password."""
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user_from_token(token: str) -> Dict[str, Any]:
    """Get current user from JWT token."""
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = USERS_DB.get(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


def check_permission(user: Dict[str, Any], permission: str) -> bool:
    """Check if user has a specific permission."""
    user_role = user.get("role", Role.VIEWER)
    user_permissions = ROLE_PERMISSIONS.get(user_role, set())
    return permission in user_permissions


def require_permission(permission: str):
    """Decorator to require a specific permission for an endpoint."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get token from request
            from fastapi import Request
            request = kwargs.get("request") or next((arg for arg in args if isinstance(arg, Request)), None)
            
            if request is None:
                raise HTTPException(status_code=500, detail="Request object not found")
            
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing or invalid authorization header",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            token = auth_header.split(" ")[1]
            user = get_current_user_from_token(token)
            
            if not check_permission(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {permission}",
                )
            
            kwargs["current_user"] = user
            return await func(*args, **kwargs)
        return wrapper
    return decorator


async def get_current_user_optional(token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get current user if token is provided, otherwise return None."""
    if not token:
        return None
    try:
        return get_current_user_from_token(token)
    except HTTPException:
        return None


class WebSocketAuthenticator:
    """WebSocket authentication helper."""
    
    @staticmethod
    async def authenticate(websocket: WebSocket) -> Dict[str, Any]:
        """Authenticate WebSocket connection using token query parameter."""
        await websocket.accept()
        
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Missing authentication token")
            raise WebSocketDisconnect(code=4001)
        
        user = get_current_user_from_token(token)
        if not user:
            await websocket.close(code=4002, reason="Invalid authentication token")
            raise WebSocketDisconnect(code=4002)
        
        return user
    
    @staticmethod
    async def require_role(websocket: WebSocket, required_role: str) -> Dict[str, Any]:
        """Authenticate and verify user role for WebSocket."""
        user = await WebSocketAuthenticator.authenticate(websocket)
        
        if user.get("role") != required_role and required_role != Role.VIEWER:
            # Admin-only endpoints
            if required_role == Role.ADMIN and user.get("role") != Role.ADMIN:
                await websocket.close(code=4003, reason="Admin access required")
                raise WebSocketDisconnect(code=4003)
        
        return user

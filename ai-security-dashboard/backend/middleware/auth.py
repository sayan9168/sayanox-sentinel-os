"""
Authentication & Authorization Module
JWT-based OAuth2 authentication with RBAC support
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import os

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production-abc123xyz789")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Token(BaseModel):
    """JWT Token response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Decoded token data schema"""
    username: Optional[str] = None
    role: Optional[str] = None
    user_id: Optional[int] = None


class User(BaseModel):
    """User schema"""
    id: int
    username: str
    email: str
    role: str  # 'admin' or 'viewer'
    disabled: bool = False


class UserCreate(BaseModel):
    """User creation schema"""
    username: str
    email: str
    password: str
    role: str = "viewer"


class UserLogin(BaseModel):
    """User login schema"""
    username: str
    password: str


# In-memory user store (replace with database in production)
USERS_DB = {
    "admin": {
        "id": 1,
        "username": "admin",
        "email": "admin@security.local",
        "hashed_password": pwd_context.hash("admin123"),
        "role": "admin",
        "disabled": False
    },
    "viewer": {
        "id": 2,
        "username": "viewer",
        "email": "viewer@security.local",
        "hashed_password": pwd_context.hash("viewer123"),
        "role": "viewer",
        "disabled": False
    }
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Authenticate a user by username and password"""
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[TokenData]:
    """Decode and validate a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        user_id: int = payload.get("user_id")
        
        if username is None:
            return None
        
        return TokenData(username=username, role=role, user_id=user_id)
    except JWTError:
        return None


def get_user_from_db(username: str) -> Optional[Dict]:
    """Get a user from the database"""
    user = USERS_DB.get(username)
    if user and not user.get("disabled", False):
        return user
    return None


def has_permission(role: str, required_role: str) -> bool:
    """Check if a role has the required permission level"""
    role_hierarchy = {"viewer": 1, "admin": 2}
    return role_hierarchy.get(role, 0) >= role_hierarchy.get(required_role, 0)

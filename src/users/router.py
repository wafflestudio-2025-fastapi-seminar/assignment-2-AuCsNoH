from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status,
    Request
)

from src.users.schemas import CreateUserRequest, UserResponse
from common.database import blocked_token_db, session_db, user_db

from users.errors import (
    EmailAlreadyExistsException,
    InvalidSessionException,
    BadAuthorizationHeaderException,
    InvalidTokenException,
    UnauthenticatedException
)

from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
import jwt

user_router = APIRouter(prefix="/users", tags=["users"])

next_user_id = 1
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET_KEY = "your_secret_key"
JWT_ALGORITHM = "HS256"


def session_expired(session: dict) -> bool:
    expires_at = session.get("expires_at")
    if not expires_at:
        return True
    return datetime.now(timezone.utc) > expires_at


def get_user_by_id(user_id: int) -> dict:
    for user in user_db:
        if user["user_id"] == user_id:
            return user
    return None


def verify_access_token(token: str) -> dict | None:
    if token in blocked_token_db:
        return None
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    global next_user_id

    user_data = request.model_dump()

    if any(user["email"] == user_data["email"] for user in user_db):
        raise EmailAlreadyExistsException()

    user_data["hashed_password"] = pwd_context.hash(user_data.pop("password"))

    user_data["user_id"] = next_user_id
    next_user_id += 1

    user_db.append(user_data)

    return UserResponse(**user_data)

@user_router.get("/me")
def get_user_info(request: Request):
    sid = request.cookies.get("sid")
    if sid:
        session = session_db.get(sid)
        if not session or session_expired(session):
            raise InvalidSessionException()
        user = get_user_by_id(session["user_id"])
        return UserResponse(**user)

    
    auth_header = request.headers.get("Authorization")  # 헤더에서 토큰 가져오기
    if auth_header:
        if not auth_header.startswith("Bearer "):
            raise BadAuthorizationHeaderException()  # ERR_007
        token = auth_header.split(" ")[1]
        payload = verify_access_token(token)  # JWT 디코드/검증
        if not payload:
            raise InvalidTokenException()  # ERR_008
        user = get_user_by_id(payload["sub"])  # sub claim에서 user_id 가져오기
        return UserResponse(**user)

    raise UnauthenticatedException()

from fastapi import APIRouter
from fastapi import Depends, Cookie, Request, status, Response

from common.database import blocked_token_db, session_db, user_db

from pydantic import BaseModel, EmailStr
import jwt
from datetime import datetime, timedelta

from passlib.context import CryptContext
from src.users.errors import (
    InvalidAccountException,
    UnauthenticatedException,
    BadAuthorizationHeaderException,
    InvalidTokenException
)

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60
JWT_SECRET_KEY = "your_secret_key"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@auth_router.post("/token")
def login_for_tokens(data: LoginRequest):
    user = next((u for u in user_db if u["email"] == data.email), None)
    if not user or not pwd_context.verify(data.password, user["hashed_password"]):
        raise InvalidAccountException()

    access_token = create_access_token(user["user_id"])
    refresh_token = create_refresh_token(user["user_id"])

    return {"access_token": access_token, "refresh_token": refresh_token}

def create_access_token(user_id: int):
    expire = datetime.utcnow() + timedelta(minutes=SHORT_SESSION_LIFESPAN)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

def create_refresh_token(user_id: int):
    expire = datetime.utcnow() + timedelta(minutes=LONG_SESSION_LIFESPAN)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


@auth_router.post("/token/refresh")
def refresh_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise UnauthenticatedException()
    if not auth_header.startswith("Bearer "):
        raise BadAuthorizationHeaderException()
    token = auth_header.split(" ")[1]

    if token in blocked_token_db:
        raise InvalidTokenException()

    payload = verify_access_token(token)
    if not payload:
        raise InvalidTokenException()

    blocked_token_db[token] = payload["exp"]

    user_id = payload["sub"]
    new_access_token = create_access_token(user_id)
    new_refresh_token = create_refresh_token(user_id)

    return {"access_token": new_access_token, "refresh_token": new_refresh_token}


def verify_access_token(token: str) -> dict | None:
    if token in blocked_token_db:
        return None
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithm=["HS256"])
    except jwt.PyJWTError:
        return None


@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def delete_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise UnauthenticatedException()
    if not auth_header.startswith("Bearer "):
        raise BadAuthorizationHeaderException()
    token = auth_header.split(" ")[1]

    payload = verify_access_token(token)
    if not payload:
        raise InvalidTokenException()

    blocked_token_db[token] = payload["exp"]

    return


@auth_router.post("/session")
def 세션로그인(data: LoginRequest, response: Response):
    user = next((u for u in user_db if u["email"] == data.email), None)
    if not user or not pwd_context.verify(data.password, user["hashed_password"]):
        raise InvalidAccountException()

    sid = str(uuid4())
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": datetime.utcnow() + timedelta(minutes=LONG_SESSION_LIFESPAN)
    }

    response.set_cookie(
        key="sid",
        value=sid,
        httponly=True,
        max_age=LONG_SESSION_LIFESPAN*60
    )

    return


@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def logout_session(response: Response, sid: str = Cookie(None)):
    if sid and sid in session_db:
        session_db.pop(sid)

        response.delete_cookie("sid")

    return
    

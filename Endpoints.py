from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, Query, Body
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from db import Sessions, Users, engine, get_db
import threading
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from os import environ as env
from functools import wraps

oauth = OAuth()

oauth.register(
    "enterprise",
    client_id=env.get("CLIENT_ID"),
    client_secret=env.get("CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("DOMAIN")}/.well-known/openid-configuration'
)

router = APIRouter()

class UserSession:
    id: str
    timer: threading.Timer
    is_admin: bool

    def __init__(self, id, timer, is_admin):
        self.id = id
        self.timer = timer
        self.is_admin = is_admin

oauth_map = dict()

# Password hashing utility
crypt_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Request models
class LoginParams(BaseModel):
    username: str
    password: str

class RegisterParams(BaseModel):
    username: str
    password: str

class CheckParams(BaseModel):
    sessionToken: str

class UserPatchParams(BaseModel):
    password: str

class AdminUserPatchParams(BaseModel):
    id: str
    username: str
    password: str

class AdminUserDeleteParams(BaseModel):
    id: str

# all of our auth modes (oauth, password) are mutually exclusive
def ensure_auth_mode(mode: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if env.get("AUTH_MODE") != mode: 
                raise HTTPException(status_code=400, detail="INVALID_AUTH_MODE")
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# (session, is_admin)
def check_session(session: str, db: Session) -> tuple[Sessions, bool]:
    twenty_four_hours_ago = datetime.now(tz=timezone.utc) - timedelta(days=2)
    session = db.query(Sessions).where(Sessions.id==session and Sessions.timestamp > twenty_four_hours_ago).first()
    if not session or session.logged_out:
        return (None, False)
    user = db.query(Users).where(Users.id==session.user_id).one()
    return (session, user.is_admin)

def create_session(user_id: str, request: Request, db: Session) -> str:
    session = Sessions(user_id=user_id, ip_address=request.client.host)
    db.add(session)
    db.commit()
    return session.id

@router.get("/oauth_login")
@ensure_auth_mode("oauth")
async def login(request: Request):
    enterprise = oauth.create_client('enterprise')
    redirect_uri = 'http://localhost:4000/authorize'
    return await enterprise.authorize_redirect(request, redirect_uri)

@router.get("/authorize")
@ensure_auth_mode("oauth")
async def authorize(request: Request, db: Session = Depends(get_db)):
    token = await oauth.enterprise.authorize_access_token(request)
    user = token['userinfo']
    oauth_map[user['email']] = token
    return create_session(user['email'], request, db) # TODO: support Oauth admin

@router.post("/register")
@ensure_auth_mode("password")
async def register(request: Request, sessionToken: str = Query(), params: RegisterParams = Body(), db: Session = Depends(get_db)):
    (session, is_admin) = check_session(sessionToken, db)
    if not session or not is_admin:
        return {"error": True, "status": "NOT_ADMIN"}

    # Check if the user already exists
    user = db.query(Users).filter(Users.username == params.username).first()
    if user:
        raise HTTPException(status_code=400, detail="USER_ALREADY_EXISTS")
    
    # Hash password before storing it
    hashed_password = crypt_ctx.hash(params.password)
    new_user = Users(username=params.username, password=hashed_password, is_admin=False)
    db.add(new_user)
    db.commit()
    
    # Create a session token for the new user
    session_token = create_session(new_user.id, request, db)
    return {"error": False, "status": "USER_REGISTERED", "data": session_token}

@router.post("/login")
@ensure_auth_mode("password")
async def login(request: Request, params: LoginParams, db: Session = Depends(get_db)):
    # Retrieve user from the database
    user = db.query(Users).filter(Users.username == params.username).first()
    
    # Check if the user exists and the password is correct
    if not user or not crypt_ctx.verify(params.password, user.password):
        raise HTTPException(status_code=400, detail="INVALID_USERNAME_OR_PASSWORD")

    # Create a session token for the user
    session_token = create_session(user.id, request, db)
    return {"error": False, "status": "SUCCESSFUL_AUTHENTICATION", "data": session_token}

@router.patch("/user")
@ensure_auth_mode("password")
async def user(sessionToken: str = Query(), params: UserPatchParams = Body(), db: Session = Depends(get_db)):
    (session, _) = check_session(sessionToken, db)
    if not session:
        return {"error": True, "status": "INVALID_SESSION"}
    
    # Retrieve user from the database
    user = db.query(Users).filter(Users.id == session.user_id).first()
    user.password = crypt_ctx.hash(params.password)
    db.commit()
    return {"error": False, "status": "USER_UPDATED"}

@router.delete("/admin/user")
@ensure_auth_mode("password")
async def user(sessionToken: str = Query(), params: AdminUserDeleteParams = Body(), db: Session = Depends(get_db)):
    (session, is_admin) = check_session(sessionToken, db)
    if not session or not is_admin:
        return {"error": True, "status": "NOT_ADMIN"}
    
    # Delete the requested user id
    db.query(Users).filter(Users.id == params.id).delete()
    db.commit()
    return {"error": False, "status": "USER_DELETED"}

@router.patch("/admin/user")
@ensure_auth_mode("password")
async def user(sessionToken: str = Query(), params: AdminUserPatchParams = Body(), db: Session = Depends(get_db)):
    (session, is_admin) = check_session(sessionToken, db)
    if not session or not is_admin:
        return {"error": True, "status": "NOT_ADMIN"}
    
    # Retrieve user from the database
    user = db.query(Users).filter(Users.id == params.id).first()
    user.username = params.username
    user.password = crypt_ctx.hash(params.password)
    db.commit()
    return {"error": False, "status": "USER_UPDATED"}

@router.get("/admin/users")
@ensure_auth_mode("password")
async def user(sessionToken: str = Query(), db: Session = Depends(get_db)):
    (session, is_admin) = check_session(sessionToken, db)
    if not session or not is_admin:
        return {"error": True, "status": "NOT_ADMIN"}
    
    # Retrieve user from the database
    users = db.query(Users).all()
    return {"error": False, "data": users}

@router.get("/sessions")
async def user(sessionToken: str = Query(), db: Session = Depends(get_db)):
    (session, _) = check_session(sessionToken, db)
    if not session:
        return {"error": True, "status": "INVALID_SESSION"}
    
    # Retrieve user from the database
    sessions = db.query(Sessions).where(Sessions.user_id==session.user_id).all()
    return {"error": False, "data": sessions}

@router.post("/check")
def check(params: CheckParams, db: Session = Depends(get_db)):
    # Verify if the session token exists in active sessions
    (session, is_admin) = check_session(params.sessionToken, db)
    if session:
        return {"error": False, "status": "SESSION_AUTHENTICATED", "id": session.user_id, "is_admin": is_admin}
    else:
        return {"error": True, "status": "INVALID_SESSION", "is_admin": False}

@router.post("/logout")
def check(params: CheckParams, db: Session = Depends(get_db)):
    (session, _) = check_session(params.sessionToken, db)
    if session:
        session.logged_out = True
    db.commit()

@router.get("/api/docs")
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url="/auth/openapi.json",
        title="Auth API Doc"
    )
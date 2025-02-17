from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from db import engine, get_db
from User import User
import secrets
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
    username: str
    timer: threading.Timer
    is_admin: bool

    def __init__(self, username, timer, is_admin):
        self.username = username
        self.timer = timer
        self.is_admin = is_admin


# Session hashmaps
token_session_map = {} # K: session_token, V: UserSession
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

SESSION_TIMEOUT_EXPIRY = 24 * 3600 * 2  # 2 days
def start_new_token_timer(token):
    if token_session_map[token].timer != None:
        token_session_map[token].timer.cancel()

    def timer_func():
        del token_session_map[token]
    timer = threading.Timer(SESSION_TIMEOUT_EXPIRY, timer_func)
    token_session_map[token].timer = timer
    timer.start()

def create_session(user_id: str, is_admin: bool) -> str:
    token = secrets.token_hex(64)
    token_session_map[token] = UserSession(user_id, None, is_admin)
    # Set a timeout to remove the session after the expiry time
    start_new_token_timer(token)
    return token

@router.get("/oauth_login")
@ensure_auth_mode("oauth")
async def login(request: Request):
    enterprise = oauth.create_client('enterprise')
    redirect_uri = 'http://localhost:4000/authorize'
    return await enterprise.authorize_redirect(request, redirect_uri)

@router.get("/authorize")
@ensure_auth_mode("oauth")
async def authorize(request: Request):
    token = await oauth.enterprise.authorize_access_token(request)
    user = token['userinfo']
    oauth_map[user['email']] = token
    return create_session(user['email'], False) # TODO: support Oauth admin

@router.post("/register")
@ensure_auth_mode("password")
async def register(params: RegisterParams, db: Session = Depends(get_db)):
    # Check if the user already exists
    user = db.query(User).filter(User.username == params.username).first()
    if user:
        raise HTTPException(status_code=400, detail="USER_ALREADY_EXISTS")
    
    # Hash password before storing it
    hashed_password = crypt_ctx.hash(params.password)
    new_user = User(username=params.username, password=hashed_password)
    
    db.add(new_user)
    db.commit()
    
    # Create a session token for the new user
    session_token = create_session(new_user.id, False) # admin can never be created via api call
    return {"error": False, "status": "USER_REGISTERED", "data": session_token}

@router.post("/login")
@ensure_auth_mode("password")
async def login(params: LoginParams, db: Session = Depends(get_db)):
    # Retrieve user from the database
    user = db.query(User).filter(User.username == params.username).first()
    
    # Check if the user exists and the password is correct
    if not user or not crypt_ctx.verify(params.password, user.password):
        raise HTTPException(status_code=400, detail="INVALID_USERNAME_OR_PASSWORD")

    # Create a session token for the user
    session_token = create_session(user.id, user.username == "admin")
    return {"error": False, "status": "SUCCESSFUL_AUTHENTICATION", "data": session_token}

@router.post("/check")
def check(params: CheckParams):
    # Verify if the session token exists in active sessions
    session_exists = params.sessionToken in token_session_map
    if session_exists:
        session = token_session_map[params.sessionToken]
        # renew the token for another set duration
        start_new_token_timer(params.sessionToken)
        return {"error": False, "status": "SESSION_AUTHENTICATED", "id": session.username, "is_admin": session.is_admin}
    else:
        return {"error": True, "status": "INVALID_SESSION", "is_admin": False}

@router.post("/logout")
def check(params: CheckParams):
    user_session = token_session_map.pop(params.sessionToken, None)
    if user_session != None:
        user_session.timer.cancel()
    return "OK"
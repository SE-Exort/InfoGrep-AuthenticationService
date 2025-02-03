from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from db import engine
from User import User
import secrets
import threading
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from os import environ as env
from dotenv import find_dotenv, load_dotenv
from functools import wraps


# Load configs for OAuth
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

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

# Session storage
token_to_id = {}
timer_map = {}

# Password hashing utility
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
def start_invalidate_token_timer(token):
    timer_map.pop(token, None) # invalidate any current timers on this token
    def timer_func():
        del token_to_id[token]
        del timer_map[token]
    timer = threading.Timer(SESSION_TIMEOUT_EXPIRY, timer_func)
    timer_map[token] = timer
    timer.start()

def create_session(user_id: str) -> str:
    token = secrets.token_hex(64)
    token_to_id[token] = user_id

    # Set a timeout to remove the session after the expiry time
    start_invalidate_token_timer(token)

    return token

def get_db():
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()

@router.get("/oauth_login")
@ensure_auth_mode("oauth")
async def login(request: Request):
    enterprise = oauth.create_client('enterprise')
    redirect_uri = 'http://localhost:4000/authorize'
    return await enterprise.authorize_redirect(request, redirect_uri)

oauth_map = dict()
@router.get("/authorize")
@ensure_auth_mode("oauth")
async def authorize(request: Request):
    token = await oauth.enterprise.authorize_access_token(request)
    user = token['userinfo']
    oauth_map[user['email']] = token
    return create_session(user['email'])

@router.post("/register")
@ensure_auth_mode("password")
def register(params: RegisterParams, db: Session = Depends(get_db)):
    # Check if the user already exists
    user = db.query(User).filter(User.username == params.username).first()
    if user:
        raise HTTPException(status_code=400, detail="USER_ALREADY_EXISTS")
    
    # Hash password before storing it
    hashed_password = pwd_context.hash(params.password)
    new_user = User(username=params.username, password=hashed_password)
    
    db.add(new_user)
    db.commit()
    
    # Create a session token for the new user
    session_token = create_session(new_user.id)
    return {"error": False, "status": "USER_REGISTERED", "data": session_token}

@router.post("/login")
@ensure_auth_mode("password")
def login(params: LoginParams, db: Session = Depends(get_db)):
    # Retrieve user from the database
    user = db.query(User).filter(User.username == params.username).first()
    
    # Check if the user exists and the password is correct
    if not user or not pwd_context.verify(params.password, user.password):
        raise HTTPException(status_code=400, detail="INVALID_USERNAME_OR_PASSWORD")
    
    # Create a session token for the user
    session_token = create_session(user.id)
    return {"error": False, "status": "SUCCESSFUL_AUTHENTICATION", "data": session_token}

@router.post("/check")
def check(params: CheckParams):
    # Verify if the session token exists in active sessions
    session_exists = any(params.sessionToken in token_to_id)
    if session_exists:
        # renew the token for another set duration
        start_invalidate_token_timer(params.sessionToken)
        return {"status": "SESSION_AUTHENTICATED", "id": token_to_id[params.sessionToken]}
    else:
        raise HTTPException(status_code=400, detail="INVALID_SESSION")

@router.post("/logout")
def check(params: CheckParams):
    del token_to_id[params.sessionToken]
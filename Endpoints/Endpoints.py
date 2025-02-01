from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import uuid
from db import engine
from User import User
import secrets
import threading

router = APIRouter()

# Session storage
sessions = {}

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

SESSION_TIMEOUT_EXPIRY = 6 * 3600  # 6 hours 
def create_session(user_id: str) -> str:
    if user_id not in sessions:
        sessions[user_id] = set()

    session_id = secrets.token_hex(64)
    sessions[user_id].add(session_id)

    # Set a timeout to remove the session after the expiry time
    threading.Timer(SESSION_TIMEOUT_EXPIRY, lambda: sessions[user_id].discard(session_id)).start()

    return session_id

def get_db():
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()

@router.post("/register")
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
    session_exists = any(params.sessionToken in tokens for tokens in sessions.values())
    if session_exists:
        return {"status": "SESSION_AUTHENTICATED"}
    else:
        raise HTTPException(status_code=400, detail="INVALID_SESSION")

import os

import passlib
import uvicorn
from fastapi import FastAPI 
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import OperationalError
from passlib.context import CryptContext

from Endpoints import router
from InfoGrep_BackendSDK.middleware import TracingMiddleware, LoggingMiddleware
from InfoGrep_BackendSDK.infogrep_logger.logger import Logger
from User import User
from db import engine, get_db
from dotenv import find_dotenv, load_dotenv
from os import environ as env


InfoGrepAuthentication = FastAPI(openapi_url="/auth/openapi.json")

# Test db connection
try:
    with engine.connect() as connection:
        print("DB connection established.")
except OperationalError as e:
    print("Unable to connect to the database:", e)
    exit(1)

os.environ["no_proxy"] = "*"
os.environ['OBJC_DISABLE_INITIALIZE_FORK_SAFETY'] = 'YES'
origins = [
    "*",
]

# Load configs for OAuth
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# If we are in auth=password mode, create the admin user if it doesn't exist
db = next(get_db())
if env.get("AUTH_MODE") == "password" and not db.query(User).filter(User.username == "admin").first():
    Logger("AuthServiceLogger").info("Creating default admin user..")
    crypt_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    new_user = User(username="admin", password=crypt_ctx.hash("aANzQ0yUl5Pa@a"))
    
    db.add(new_user)
    db.commit()

InfoGrepAuthentication.add_middleware(TracingMiddleware)
InfoGrepAuthentication.add_middleware(LoggingMiddleware, logger=Logger("AuthServiceLogger"))
InfoGrepAuthentication.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
InfoGrepAuthentication.add_middleware(SessionMiddleware, secret_key="some-random-string")

InfoGrepAuthentication.include_router(router)


if __name__ == "__main__":
    uvicorn.run(InfoGrepAuthentication, host="0.0.0.0", port=4000)
    

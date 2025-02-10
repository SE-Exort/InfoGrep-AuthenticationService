import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import OperationalError

from Endpoints import router
from InfoGrep_BackendSDK.middleware import TracingMiddleware, LoggingMiddleware
from InfoGrep_BackendSDK.infogrep_logger.logger import Logger
from db import engine

InfoGrepAuthentication = FastAPI()

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
    
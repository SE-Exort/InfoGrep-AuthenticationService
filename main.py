from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
from sqlalchemy.exc import OperationalError
from Endpoints import router
from starlette.middleware.sessions import SessionMiddleware
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

@InfoGrepAuthentication.middleware("http")
async def add_open_telemetry_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in request.headers.items():
        if k.startswith("x-") or k.startswith("trace"):
            response.headers[k] = v
    return response

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

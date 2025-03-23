from sqlalchemy import Boolean, DateTime, create_engine, func
import os
from sqlalchemy.orm import Session, declarative_base
from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
import uuid

from InfoGrep_BackendSDK.infogrep_logger.logger import Logger
# DB config
db_port = "5432"
db_host = os.environ.get("PGHOST", f"localhost:{db_port}")
db_user = os.environ.get("POSTGRES_USERNAME", "postgres")
db_password = os.environ.get("POSTGRES_PASSWORD", "example")
db_name = os.environ.get("PG_DATABASE_NAME", "postgres")
logger = Logger("AuthServiceLogger")

DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}/{db_name}"

engine = None

# Create SQLAlchemy engine
if os.environ.get("PG_VERIFY_CERT") == "true":
    ca_cert_path = os.environ["PG_CA_CERT_PATH"]
    client_cert_path = os.environ["PG_TLS_CERT_PATH"]
    client_key_path = os.environ["PG_TLS_KEY_PATH"]
    ssl_args = {
        'sslrootcert':ca_cert_path,
        'sslcert':client_cert_path,
        'sslkey':client_key_path
    }
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=ssl_args)
    logger.info("SSL DB engine created")

else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    logger.info("DB engine created")

def get_db():
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()

# Creates a base class
Base = declarative_base()

class Users(Base):
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    username = Column(String(128), nullable=False)
    password = Column(String(128), nullable=False)
    is_admin = Column(Boolean(), nullable=False)
    oauth = Column(Boolean(), nullable=False)

class Sessions(Base):
    __tablename__ = 'sessions'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    user_id = Column(UUID(as_uuid=True), nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    logged_out = Column(Boolean(), nullable=False, default=False)
    ip_address = Column(String(), nullable=False)

# Create all tables in db
Base.metadata.create_all(engine)
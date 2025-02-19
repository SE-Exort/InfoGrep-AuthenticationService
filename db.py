from sqlalchemy import create_engine
import os
from sqlalchemy.orm import Session

# DB config
db_port = "5432"
db_host = os.environ.get("PGHOST", f"auth-service-postgres:{db_port}")
db_user = os.environ.get("POSTGRES_USERNAME", "postgres")
db_password = os.environ.get("POSTGRES_PASSWORD", "example")
db_name = os.environ.get("PG_DATABASE_NAME", "postgres")

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
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

def get_db():
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()
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

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

def get_db():
    db = Session(bind=engine)
    try:
        yield db
    finally:
        db.close()
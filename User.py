from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
import uuid
from db import engine

# Creates a base class
Base = declarative_base()

# Creates the User class
class User(Base):
    __tablename__ = 'users'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    username = Column(String(128), nullable=False)
    password = Column(String(128), nullable=False)

# Create all tables in db
Base.metadata.create_all(engine)

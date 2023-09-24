from sqlalchemy import create_engine
from contacts.models import Base
from decouple import config

DATABASE_URL = config("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)

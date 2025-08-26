# shared/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://root:OgdeXuuOLQPDnMsMqxXlcNVUvFKSgPaL@cybernova.railway.internal:3306/railway")

engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    # Import models so Base.metadata knows about them
    import shared.models  # noqa
    Base.metadata.create_all(bind=engine)



import os

from sqlmodel import create_engine, SQLModel, Session

# The database URL tells SQLAlchemy where our database is located.
# "sqlite:///database.db" means we are using SQLite, and the database
# file is named "database.db" in the same directory.
DATABASE_URL = "sqlite:///database.db"

# The engine is the central point of communication with the database.
# connect_args is needed only for SQLite to allow sharing the connection
# across different threads, which is important for FastAPI.
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})


def create_db_and_tables():
    """
    Initializes the database and creates all tables defined by SQLModel models.
    This function should be called once when the application starts.
    """
    SQLModel.metadata.create_all(engine)


def get_session():
    """
    A dependency function to get a database session for each request.
    It will automatically be closed after the request is finished.
    """
    with Session(engine) as session:
        yield session


def create_session() -> Session:
    """
    Create a new database session for manual lifecycle management.
    The caller is responsible for closing the session when done.
    Use this for long-lived connections (e.g., protocol servers).
    """
    return Session(engine)


def cleanup(db_file: str = "database.db"):
    """Removes the database file."""
    if os.path.exists(db_file):
        os.remove(db_file)
        print(f"Removed database file: {db_file}")


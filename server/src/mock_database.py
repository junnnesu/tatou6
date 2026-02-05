"""
Mock Database for Unit Testing
When TESTMODE environment variable is set, use in-memory SQLite instead of MySQL
"""
import os
from sqlalchemy import create_engine, text

def get_test_engine():
    """Create an in-memory SQLite engine for testing"""
    engine = create_engine("sqlite:///:memory:", future=True)

    # Create tables matching the production schema
    with engine.begin() as conn:
        # Users table
        conn.execute(text("""
            CREATE TABLE Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                login TEXT UNIQUE NOT NULL,
                hpassword TEXT NOT NULL,
                creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        # Documents table
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                ownerid INTEGER NOT NULL,
                sha256 TEXT,
                size INTEGER,
                creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ownerid) REFERENCES Users(id)
            )
        """))

        # Versions table
        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                documentid INTEGER NOT NULL,
                link TEXT UNIQUE NOT NULL,
                intended_for TEXT,
                secret TEXT,
                method TEXT,
                position TEXT,
                path TEXT,
                creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (documentid) REFERENCES Documents(id) ON DELETE CASCADE
            )
        """))

    return engine

def is_test_mode():
    """Check if we're in test mode"""
    return os.environ.get("TESTMODE", "").strip() in ("1", "true", "True", "TRUE")

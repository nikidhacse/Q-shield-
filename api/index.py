import sys
import os

# Ensure the root directory is on the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app

# Ensure database tables are created on startup if using SQLite
try:
    from app.core.database import Base, engine
    Base.metadata.create_all(bind=engine)
except Exception:
    pass

import sys
import os

# Ensure the root directory is on the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Ensure models are loaded and tables created
try:
    import app.models  # noqa: F401
    from app.core.database import Base, engine
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"Database initialization warning: {e}")

from app.main import app

from app import app
from models import db
from cert_service import init_ca

with app.app_context():
    db.create_all()
    print("Database tables created.")

init_ca()
print("Initialization complete. Run `uv run app.py` to start the server.")
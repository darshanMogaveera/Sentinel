from flask import Flask
from backend.database.db_models import db

def init_db(app: Flask):
    """
    Initialize the database with the Flask app context.
    """
    if "sqlalchemy" not in app.extensions:
        db.init_app(app)
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Safe migration for run_id
        from sqlalchemy import text
        try:
            db.session.execute(text("ALTER TABLE predictions ADD COLUMN run_id VARCHAR(50)"))
            db.session.commit()
        except Exception:
            # Column likely already exists
            db.session.rollback()

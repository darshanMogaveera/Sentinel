from flask import Blueprint, jsonify
from datetime import datetime
from backend.services.live_inference_service import live_inference_service
from backend.services.threat_detection_service import threat_service
from backend.database.db_models import db

health_bp = Blueprint('health', __name__, url_prefix='/api/health')

@health_bp.route('/status', methods=['GET'])
def health_status():
    """
    GET /api/health/status
    """
    models_loaded = bool(
        live_inference_service.models_loaded or
        (threat_service.rf_model is not None) or
        (threat_service.if_model is not None)
    )
    
    db_connected = False
    try:
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        db_connected = True
    except Exception:
        db_connected = False
        
    return jsonify({
        "status": "healthy" if (models_loaded and db_connected) else "degraded",
        "models_loaded": models_loaded,
        "database_connected": db_connected,
        "timestamp": datetime.utcnow().isoformat()
    })

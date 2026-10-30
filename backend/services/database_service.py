from backend.database.db_models import db, Prediction, Alert
from datetime import datetime, timedelta

class DatabaseService:
    
    def save_prediction(self, prediction_data: dict) -> str:
        """Save prediction to database, return prediction_id or None on failure"""
        try:
            new_prediction = Prediction(
                source_ip=prediction_data.get('source_ip', ''),
                dest_ip=prediction_data.get('dest_ip', ''),
                threat=prediction_data.get('threat', False),
                confidence=prediction_data.get('confidence', 0.0),
                threat_type=prediction_data.get('threat_type', 'normal'),
                explanation=prediction_data.get('explanation', ''),
                rf_prediction=prediction_data.get('rf_prediction', 0),
                if_prediction=prediction_data.get('if_prediction', 1),
                run_id=prediction_data.get('run_id')
            )
            db.session.add(new_prediction)
            db.session.commit()
            return new_prediction.id
        except Exception as e:
            db.session.rollback()
            from backend.services.logging_service import logger_service
            logger_service.log_error(e, {"context": "DatabaseService.save_prediction"})
            return None
    
    def save_alert(self, prediction_id: str, severity: str = 'medium') -> str:
        """Save alert to database, return alert_id or None on failure"""
        try:
            new_alert = Alert(
                prediction_id=prediction_id,
                status='active',
                severity=severity
            )
            db.session.add(new_alert)
            db.session.commit()
            print(f"DEBUG: Successfully saved alert {new_alert.id} for prediction {prediction_id}")
            return new_alert.id
        except Exception as e:
            print(f"DEBUG ERROR saving alert: {e}")
            db.session.rollback()
            from backend.services.logging_service import logger_service
            logger_service.log_error(e, {"context": "DatabaseService.save_alert", "prediction_id": prediction_id})
            return None
    
    def get_prediction_history(self, limit: int = 100):
        """Retrieve recent predictions"""
        predictions = Prediction.query.order_by(Prediction.timestamp.desc()).limit(limit).all()
        return [{
            "id": p.id,
            "source_ip": p.source_ip,
            "dest_ip": p.dest_ip,
            "threat": p.threat,
            "confidence": p.confidence,
            "threat_type": p.threat_type,
            "explanation": p.explanation,
            "timestamp": p.timestamp.isoformat()
        } for p in predictions]
    
    def get_observed_devices(self, run_id: str = None):
        """Aggregate devices by source_ip from predictions, optionally filtered by run_id"""
        from sqlalchemy import func
        
        query = db.session.query(
            Prediction.source_ip,
            func.min(Prediction.timestamp).label('first_seen'),
            func.max(Prediction.timestamp).label('last_seen'),
            func.count(Prediction.id).label('predictions'),
            func.count(Alert.id).label('threats')
        ).outerjoin(Alert, Prediction.id == Alert.prediction_id)
        
        if run_id:
            query = query.filter(Prediction.run_id == run_id)
            
        devices = query.group_by(Prediction.source_ip).all()
        
        return [{
            "ip": d.source_ip,
            "first_seen": d.first_seen.isoformat() if d.first_seen else None,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "predictions": d.predictions,
            "threats": int(d.threats or 0)
        } for d in devices]
    
    def get_alerts(self, limit: int = 20) -> list:
        """Get all alerts ordered by descending timestamp"""
        alerts = db.session.query(Alert, Prediction).join(Prediction).order_by(Prediction.timestamp.desc()).limit(limit).all()
        return [{
            "alert_id": a.id,
            "prediction_id": p.id,
            "threat": p.threat,
            "confidence": p.confidence,
            "source_ip": p.source_ip,
            "dest_ip": p.dest_ip,
            "threat_type": p.threat_type,
            "explanation": p.explanation,
            "timestamp": p.timestamp.isoformat(),
            "status": a.status,
            "severity": a.severity
        } for a, p in alerts]
        
    def get_alert_stats(self) -> dict:
        """Get stats for summary cards"""
        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        total = db.session.query(Alert).count()
        active = db.session.query(Alert).filter(Alert.status == 'active').count()
        high_conf = db.session.query(Alert).join(Prediction).filter(Prediction.confidence >= 0.8).count()
        recent = db.session.query(Alert).join(Prediction).filter(Prediction.timestamp >= twenty_four_hours_ago).count()
        
        return {
            "total": total,
            "active": active,
            "high_confidence": high_conf,
            "recent_24h": recent
        }
    
    def get_active_alerts(self) -> list:
        """Get unresolved alerts"""
        alerts = db.session.query(Alert, Prediction).join(Prediction).filter(Alert.status == 'active').all()
        return [{
            "alert_id": a.id,
            "prediction_id": p.id,
            "threat": p.threat,
            "confidence": p.confidence,
            "source_ip": p.source_ip,
            "dest_ip": p.dest_ip,
            "explanation": p.explanation,
            "timestamp": a.timestamp.isoformat(),
            "status": a.status,
            "severity": a.severity
        } for a, p in alerts]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark alert as acknowledged"""
        alert = Alert.query.get(alert_id)
        if alert:
            alert.status = 'acknowledged'
            db.session.commit()
            return True
        return False
        
    def resolve_alert(self, alert_id: str) -> bool:
        """Mark alert as resolved"""
        alert = Alert.query.get(alert_id)
        if alert:
            alert.status = 'resolved'
            db.session.commit()
            return True
        return False

# Singleton instance
db_service = DatabaseService()

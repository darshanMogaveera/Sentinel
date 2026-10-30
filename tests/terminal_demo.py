import warnings
warnings.filterwarnings('ignore')

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Suppress scapy warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import json
from backend.flask_api.app import create_app
from backend.database.db_init import init_db
from backend.services.live_inference_service import live_inference_service

app = create_app('development')
init_db(app)

with app.app_context():
    with open('frontend/src/sample_packet.json', 'r') as f:
        packet = json.load(f)

    result = live_inference_service.predict(
        packet['features'],
        packet['flow_meta'],
        run_id='concise_demo',
        skip_correlation=True
    )

    status = "ATTACK DETECTED" if result.get('threat') else "NORMAL / BENIGN"
    threat_type = result.get('threat_type')
    confidence = result.get('confidence', 0.0) * 100

    print("==================================================")
    print(f" RESULT:         {status}")
    print(f" CLASSIFICATION: {threat_type}")
    print(f" CONFIDENCE:     {confidence:.1f}%")
    print("==================================================")

    explanation = json.loads(result['explanation'])
    print(f"\nSummary:\n  {explanation.get('text')}\n")

    print("Why Sentinel made this decision (Top Features):")
    print("-" * 50)
    for i, feat in enumerate(explanation.get('top_features', []), 1):
        direction = "Toward Threat" if feat['impact'] > 0 else "Away from Threat"
        print(f"  {i}. {feat['feature']:<28} | Impact: {feat['impact']:>+7.4f} ({direction})")
    print("-" * 50)

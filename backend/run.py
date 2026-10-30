import os
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.flask_api.app import create_app
from backend.database.db_init import init_db

if __name__ == '__main__':
    app = create_app('development')
    init_db(app) 
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

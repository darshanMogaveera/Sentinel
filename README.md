# 🛡️ Sentinel

### AI-Powered IoT & Network Threat Detection System

<p align="center">
  <strong>Real-Time Network Monitoring • Machine Learning Detection • Explainable Alerts</strong>
</p>

<p align="center">
  Sentinel monitors network traffic, converts packets into behavioral flow features, detects PortScan activity using XGBoost, and presents explainable security alerts through a real-time web dashboard.
</p>

<p align="center">

![Status](https://img.shields.io/badge/Status-Validated-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-61DAFB)
![Flask](https://img.shields.io/badge/Backend-Flask-000000)
![ML](https://img.shields.io/badge/ML-XGBoost-orange)
![NFStream](https://img.shields.io/badge/Traffic-NFStream-blue)
![Database](https://img.shields.io/badge/Database-SQLite-003B57)
![License](https://img.shields.io/badge/Project-Academic%20Prototype-lightgrey)

</p>

---

## 📸 Sentinel in Action

### 🔴 PortScan Detection

> Controlled network scan detected in real time by Sentinel.

<!-- Add your Security Alerts screenshot here -->

`Source → Destination` • `PortScan` • `97.8% confidence` • `ACTIVE`

### 📡 Live Network Monitoring

> Real Wi-Fi traffic captured and analyzed through the complete Sentinel pipeline.

<!-- Add your Live Monitor screenshot here -->

`12,264 packets` • `2,193 flows` • `2,193 predictions` • `1 threat alert` • `0 inference errors`

---

# 🎯 What is Sentinel?

**Sentinel** is a software-based IoT and network threat detection system designed as a final-year engineering project.

It continuously monitors network traffic and analyzes communication behavior at the **flow level** rather than inspecting individual packets independently.

The system converts captured network traffic into **69 statistical flow features**, processes those features through a trained **XGBoost classifier**, and identifies whether network behavior is:

* 🟢 **BENIGN**
* 🔴 **PORTSCAN**

When a PortScan is detected, Sentinel records the event in SQLite and presents the detection through its React dashboard.

### In simple terms

Think of Sentinel as a **network security guard**:

```text
Network Traffic
      ↓
Observe communication
      ↓
Understand traffic behavior
      ↓
ML-based detection
      ↓
BENIGN / PORTSCAN
      ↓
Explain + Record
      ↓
Security Dashboard
```

---

# ✨ Key Features

| Feature                        | Description                                                     |
| ------------------------------ | --------------------------------------------------------------- |
| 📡 **Real-Time Capture**       | Captures live network traffic through NFStream/Npcap            |
| 🔄 **Flow Aggregation**        | Converts packets into bidirectional network flows               |
| 🧠 **Machine Learning**        | XGBoost-based PortScan detection                                |
| 📊 **69 Features**             | CICFlowMeter-compatible statistical flow representation         |
| 🔍 **Explainable Detection**   | Feature-level model contributions help explain predictions      |
| 🚨 **Security Alerts**         | Detected threats are persisted and displayed in the dashboard   |
| 💾 **SQLite Logging**          | Predictions and alerts are stored for historical analysis       |
| 🌐 **Web Dashboard**           | React + TypeScript interface for monitoring                     |
| 🖥️ **Device Visibility**      | Displays observed network devices and their activity            |
| 🧪 **Controlled Validation**   | Tested using real Wi-Fi traffic and controlled PortScan traffic |
| ⚡ **Lightweight Architecture** | Designed around flow-level features and classical ML            |

---

# 🏗️ System Architecture

The current production pipeline is:

```text
                    NETWORK
                      │
                      ▼
              ┌───────────────┐
              │ Npcap / OS NIC │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │   NFStream    │
              │ Packet → Flow │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ 69 Flow-Level │
              │   Features    │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │    Scaler     │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │    XGBoost    │
              │   Classifier  │
              └───────┬───────┘
                      │
              ┌───────┴────────┐
              ▼                ▼
           BENIGN           PORTSCAN
                                │
                                ▼
                     Behavioral Correlation
                                │
                                ▼
                         Security Alert
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
             SQLite                    Explainable Output
                 │                             │
                 └──────────────┬──────────────┘
                                ▼
                       Flask REST API
                                │
                                ▼
                    React / TypeScript UI
```

### Why flow-level detection?

Instead of treating every packet independently, Sentinel aggregates network communication into flows.

A flow contains behavioral information such as:

* packet counts
* byte counts
* packet sizes
* duration
* packet rates
* forward/backward traffic
* TCP/UDP/ICMP information
* protocol behavior

This provides the ML model with a statistical representation of network communication.

---

# 🤖 Machine Learning Pipeline

## Production Model

The current production detector uses:

**XGBoost + StandardScaler**

Production artifacts:

```text
backend/
└── models/
    └── live_nfstream/
        ├── final_xgboost_model.joblib
        ├── scaler.joblib
        ├── feature_names.joblib
        ├── label_encoder.joblib
        └── metadata.json
```

### Feature Pipeline

```text
Network Packets
      ↓
NFStream
      ↓
Flow Aggregation
      ↓
69 Features
      ↓
StandardScaler
      ↓
XGBoost
      ↓
BENIGN / PORTSCAN
```

The same NFStream-based feature generation process is used for training and live inference so that the model receives the same feature representation in both environments.

---

# 🧠 Detection Logic

Sentinel uses two stages for PortScan detection.

### Stage 1 — Machine Learning

The XGBoost classifier evaluates each network flow:

```text
69 Features
     ↓
XGBoost
     ↓
BENIGN
   or
PORTSCAN candidate
```

### Stage 2 — Behavioral Correlation

For PortScan candidates, Sentinel also examines traffic behavior over time.

The current correlation layer looks for repeated connections involving:

* source IP
* destination IP
* multiple destination ports
* a sliding time window

This helps distinguish isolated unusual flows from coordinated port-probing behavior.

### Result

```text
XGBoost PortScan Candidate
          ↓
Behavioral Correlation
          ↓
Confirmed Threat
          ↓
SQLite Alert
          ↓
Dashboard
```

---

# 🔍 Explainable Detection

Sentinel is designed to provide more than a simple:

> ❌ "Attack detected"

The system also exposes the network-flow characteristics contributing to the model decision.

Example information can include:

```text
Protocol
Forward packets
Backward packets
Average packet size
Destination port
Traffic rate
Feature contributions
```

This helps answer:

> **"Why did Sentinel consider this traffic suspicious?"**

The explanation is generated from the model's feature-level contribution information rather than from a hardcoded message.

---

# 📊 Validation Results

The production detector was evaluated using temporally separated data and controlled network traffic.

## PortScan Temporal Validation

| Metric              |     Result |
| ------------------- | ---------: |
| Accuracy            | **99.79%** |
| Recall              | **99.60%** |
| False Positive Rate |  **0.01%** |

The test set was kept separate from the training period to provide a more realistic temporal validation.

---

## Benign Regression

A separate benign-flow regression test was performed through the live Sentinel database path.

| Metric                 |    Result |
| ---------------------- | --------: |
| Benign flows processed | **5,000** |
| ML-positive candidates |    **48** |
| Final alerts           |     **0** |
| Candidate-level FPR    | **0.96%** |
| Final alert FPR        |    **0%** |

The distinction between **ML candidates** and **final correlated alerts** is intentional.

---

## Controlled Real Network Validation

Sentinel was also tested against a real local Wi-Fi network.

Example controlled PortScan:

```text
Scanner
10.12.229.185
      │
      │ Nmap TCP scan
      ▼
Sentinel
10.12.229.77
      │
      ▼
PortScan Detection
```

Observed result:

```text
12,264 packets
2,193 flows
2,193 predictions
1 threat alert
0 inference errors
```

Detected event:

```text
Source:       10.12.229.185
Destination:  10.12.229.77
Threat:       PortScan
Confidence:   97.8%
Status:       ACTIVE
```

This validation demonstrated the complete path:

```text
Real Network Traffic
        ↓
NFStream
        ↓
Feature Extraction
        ↓
XGBoost
        ↓
Behavioral Correlation
        ↓
SQLite
        ↓
Flask API
        ↓
React Dashboard
```

---

# 🖥️ Dashboard

The Sentinel interface provides several monitoring views.

### 📊 Dashboard

Provides a high-level network security overview:

* total predictions
* detected threats
* system health
* network activity
* active threat types
* recent alerts

### 📡 Live Monitor

Provides real-time monitoring:

* capture source
* packets captured
* flows aggregated
* model predictions
* threat alerts
* inference errors
* observed devices

The capture source is dynamically displayed based on the selected interface:

```text
Simulation
→ CURRENT SIMULATION

Wi-Fi
→ CURRENT CAPTURE — Wi-Fi

Ethernet
→ CURRENT CAPTURE — Ethernet
```

### 🚨 Security Alerts

Displays detected threats with:

* timestamp
* alert ID
* source
* destination
* threat type
* confidence
* status

### 🧪 Prediction Test

Allows a single flow to be evaluated using the same production XGBoost model and 69-feature pipeline used by the live detector.

---

# 🔌 API

Sentinel exposes a Flask REST API consumed by the React frontend.

## Dashboard

| Method | Endpoint                         | Purpose                    |
| ------ | -------------------------------- | -------------------------- |
| `GET`  | `/api/dashboard/stats`           | Dashboard statistics       |
| `GET`  | `/api/dashboard/activity`        | Recent prediction activity |
| `GET`  | `/api/dashboard/threat-timeline` | Threat timeline            |

## Alerts

| Method | Endpoint       | Purpose                  |
| ------ | -------------- | ------------------------ |
| `GET`  | `/api/alerts/` | Retrieve security alerts |

## Live Monitoring

| Method | Endpoint               | Purpose                           |
| ------ | ---------------------- | --------------------------------- |
| `GET`  | `/api/live/status`     | Current capture state             |
| `GET`  | `/api/live/interfaces` | Available capture interfaces      |
| `GET`  | `/api/live/devices`    | Observed devices                  |
| `POST` | `/api/live/start`      | Start packet capture              |
| `POST` | `/api/live/stop`       | Stop packet capture               |
| `POST` | `/api/live/simulate`   | Run controlled traffic simulation |

## Prediction

| Method | Endpoint                   | Purpose                                   |
| ------ | -------------------------- | ----------------------------------------- |
| `POST` | `/api/predictions/detect`  | Analyze a flow using the production model |
| `GET`  | `/api/predictions/history` | Retrieve prediction history               |

## Health

| Method | Endpoint             | Purpose                       |
| ------ | -------------------- | ----------------------------- |
| `GET`  | `/api/health/status` | Backend/database/model health |

---

# 🧰 Technology Stack

### Backend

* **Python 3.11+**
* **Flask**
* **NFStream**
* **Npcap**
* **XGBoost**
* **Scikit-learn**
* **SHAP / model contribution analysis**
* **SQLite**

### Frontend

* **React**
* **TypeScript**
* **Vite**
* **Tailwind CSS**
* **Recharts**
* **Axios**

### Testing & Validation

* Controlled local network traffic
* Real Wi-Fi traffic
* Nmap PortScan
* PCAP-based validation
* API regression tests
* Model validation datasets

---

# 📁 Project Structure

```text
iot_project/
│
├── backend/
│   ├── flask_api/
│   │   ├── routes/
│   │   │   ├── alert_routes.py
│   │   │   ├── dashboard_routes.py
│   │   │   ├── device_routes.py
│   │   │   ├── health_routes.py
│   │   │   ├── live_routes.py
│   │   │   └── prediction_routes.py
│   │   │
│   │   ├── app.py
│   │   └── config.py
│   │
│   ├── models/
│   │   ├── live_nfstream/
│   │   │   ├── final_xgboost_model.joblib
│   │   │   ├── scaler.joblib
│   │   │   ├── feature_names.joblib
│   │   │   ├── label_encoder.joblib
│   │   │   └── metadata.json
│   │   │
│   │   └── archive/
│   │
│   ├── services/
│   │   ├── database_service.py
│   │   ├── live_inference_service.py
│   │   ├── packet_capture_service.py
│   │   └── ...
│   │
│   └── run.py
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── LiveMonitor.tsx
│   │   │   ├── Alerts.tsx
│   │   │   └── Prediction.tsx
│   │   ├── api/
│   │   └── components/
│   │
│   └── package.json
│
├── tests/
│   ├── test_api.py
│   ├── test_portscan.py
│   ├── test_simulations.py
│   ├── test_e2e_final.py
│   └── ...
│
├── scripts/
│   ├── clear_runtime_db.py
│   ├── analyze_portscan_genuine.py
│   └── legacy_archive/
│
├── docs/
│   └── SENTINEL_COMPLETE_PROJECT_DOCUMENTATION.md
│
├── FINAL_MODEL_DECISION.md
├── README.md
└── requirements.txt
```

---

# 🚀 Running Sentinel

## Prerequisites

Install:

* Python 3.11+
* Node.js
* Npcap
* Git

A Windows environment with a supported network interface is required for live packet capture.

---

## 1. Clone the Repository

```bash
git clone https://github.com/armanish78/iot_project.git
cd iot_project
```

---

## 2. Create / Activate Python Environment

### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

---

## 3. Start the Backend

From the project root:

```powershell
.\venv\Scripts\python.exe backend\run.py
```

The Flask backend will start locally.

---

## 4. Start the Frontend

Open a second terminal.

From:

```text
iot_project/frontend
```

run:

```powershell
npm install
npm run dev
```

---

## 5. Open Sentinel

Open the local Vite address shown in the terminal, normally:

```text
http://localhost:5173
```

---

# 📡 Running Live Detection

1. Open **Live Monitor**
2. Select a network interface
3. Select **Wi-Fi**, Ethernet, Loopback, or another available interface
4. Click **Start Capture**
5. Generate normal network traffic
6. Sentinel aggregates packets into flows
7. The ML model evaluates each flow
8. PortScan candidates pass through behavioral correlation
9. Confirmed threats appear under **Security Alerts**

For controlled validation, a separate machine on the same local network can generate a PortScan using Nmap.

Example:

```bash
nmap -p 1-1000 <SENTINEL_IP>
```

> Only perform network scans against systems you own or have explicit permission to test.

---

# 🎓 Academic Scope

Sentinel was developed as a final-year academic project focused on software-based network monitoring and threat detection for IoT environments.

The project addresses the need for a system that can:

* monitor network traffic without modifying IoT devices
* analyze network behavior
* detect suspicious traffic using machine learning
* generate security alerts
* provide explainable detection information
* maintain historical security records
* provide a user-facing monitoring dashboard

The architecture is designed so additional attack-specific models can be incorporated in future work.

---

# ⚠️ Limitations & Honest Scope

Sentinel is an **academic research prototype**, not a commercial enterprise IDS.

### Current production detector

The current production ML model is specifically trained and validated for:

> **PortScan detection**

Therefore, Sentinel should **not** currently be described as a detector for every possible IoT attack.

Additional attack classes such as:

* DDoS
* brute-force attacks
* web attacks
* botnet command-and-control
* exploitation attempts
* ARP/MITM attacks

would require additional training data, feature validation, and attack-specific evaluation.

### Important limitations

* No claim of 100% detection
* No claim of zero false positives
* No claim of universal IoT attack detection
* No claim of complete zero-day protection
* No claim that PortScan is the only possible IoT attack entry point
* Real-world performance can vary depending on network environment and traffic characteristics

The current system should therefore be understood as a **validated software-based network threat detection prototype with PortScan detection**, rather than a complete enterprise cybersecurity platform.

---

# 🔮 Future Work

Potential future extensions include:

```text
Current
   │
   ├── PortScan Detection
   ├── Real-Time Monitoring
   ├── Explainable Alerts
   └── SQLite Logging
           │
           ▼
Future
   ├── Additional Attack Classes
   ├── General Anomaly Detection
   ├── Adaptive Behavioral Baselines
   ├── Automated Security Reports
   ├── Larger IoT Validation
   └── Extended Performance Evaluation
```

These extensions require independent validation before being considered part of the production detection capability.

---

# 📚 Documentation

Detailed technical documentation is available in:

```text
docs/SENTINEL_COMPLETE_PROJECT_DOCUMENTATION.md
```

Additional model decisions and validation information:

```text
FINAL_MODEL_DECISION.md
```

---

# 🧪 Validation Philosophy

Sentinel follows an evidence-based validation approach.

Instead of relying only on offline accuracy, the system is tested through multiple layers:

```text
Offline Dataset Validation
          ↓
PCAP Validation
          ↓
Backend/API Validation
          ↓
Database Validation
          ↓
Controlled Network Traffic
          ↓
Real Wi-Fi Traffic
          ↓
End-to-End Detection
```

This helps verify that the model is not only producing predictions in isolation, but that those predictions successfully travel through the complete application pipeline.

---

# 👨‍💻 Project

**Sentinel — AI-Powered IoT & Network Threat Detection System**

Final-year engineering project focused on:

> **Real-Time Network Monitoring + Machine Learning + Explainable Threat Detection**

---

<p align="center">
  <strong>🛡️ Detect • Analyze • Explain • Protect</strong>
</p>

<p align="center">
  Built as an academic proof-of-concept for intelligent IoT and network security monitoring.
</p>

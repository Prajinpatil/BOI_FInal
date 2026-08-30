# NIRIKSHAK-AI 🛡️ 
**Generative AI-Powered Mobile Banking Malware Analysis System**

![NIRIKSHAK-AI Banner](https://img.shields.io/badge/Security-Critical-red.svg)
![React](https://img.shields.io/badge/Frontend-React%20%7C%20Vite-20232A?style=flat&logo=react&logoColor=61DAFB)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=FastAPI&logoColor=white)
![Python](https://img.shields.io/badge/Language-Python%203.10-3776AB?style=flat&logo=python&logoColor=white)
![Groq](https://img.shields.io/badge/AI_Engine-Groq_llama_3.3_70b-f39c12?style=flat)
![VirusTotal](https://img.shields.io/badge/Dynamic_Sandbox-VirusTotal-blue?style=flat)

Welcome to **NIRIKSHAK-AI**, a state-of-the-art automated malware analysis platform built specifically to protect the digital financial ecosystem from zero-day Android Banking Trojans.

By synthesizing **Static Analysis, Dynamic Cloud Execution, Machine Learning, and Generative AI Reverse Engineering**, NIRIKSHAK-AI drastically reduces the time required for threat intelligence teams to dissect malicious APKs from days to less than 30 seconds.

---

## 📖 Table of Contents
1. [The Problem Statement](#-the-problem-statement)
2. [Our Innovative Solution](#-our-innovative-solution)
3. [The 5-Factor Risk Fusion Architecture](#-the-5-factor-risk-fusion-architecture)
4. [Deep Dive: Pipeline Components](#-deep-dive-pipeline-components)
5. [Key Features & Deliverables](#-key-features--deliverables)
6. [Tech Stack](#-tech-stack)
7. [Installation & Setup](#-installation--setup)
8. [API Documentation](#-api-documentation)
9. [Future Roadmap](#-future-roadmap)

---

## 🛑 The Problem Statement
Fraudsters are increasingly distributing malicious mobile applications (APKs) through platforms such as WhatsApp, SMS, email, and phishing links to steal customer credentials, intercept OTPs, and perform unauthorized financial transactions. 

Traditional manual analysis of such APKs is incredibly complex, time-consuming, and entirely dependent on highly skilled cybersecurity experts. Existing automated tools are often rule-based, easily bypassed by obfuscation, and fail to provide actionable context to the victims or the banks.

---

## 💡 Our Innovative Solution
NIRIKSHAK-AI acts as an autonomous cybersecurity expert. It completely automates the reverse engineering process by leveraging **Generative AI (Groq llama-3.3-70b)** to read decompiled Java bytecode and understand the developer's *intent*. 

We complement this GenAI capability with robust static parsing (Androguard) and dynamic cloud execution (VirusTotal), culminating in an enterprise-grade PDF incident response report. 

---

## 🧠 The 5-Factor Risk Fusion Architecture

To avoid false positives and detect zero-day evasions, our proprietary **Risk Fusion Engine** calculates a unified severity score (0-100) using five heavily weighted components:

1. **XGBoost ML Pattern Recognition (35%)**: 
   - We extract Android Manifest permissions and API calls and feed them into a high-speed inference engine trained on the *CICMalDroid2020* dataset.
2. **GenAI Semantic Analysis (40%)**: 
   - The system slices the Dalvik executable (DEX), extracts suspicious Java methods, and prompts Groq AI to interpret the bytecode logic (e.g., detecting `SMS_INTERCEPT_STEAL`).
3. **Dynamic Sandbox Execution (25%)**: 
   - The APK is securely uploaded to VirusTotal's cloud sandbox. We monitor network communications, dropped files, and cross-reference behavior against 70+ AV engines.
4. **Static Permission Danger Matrix (Multiplier)**: 
   - Flags dangerous permission clusters (e.g., `BIND_ACCESSIBILITY_SERVICE` + `RECEIVE_SMS`).
5. **Indian Banking Target Bonus (+15 pts)**: 
   - Statically detects hardcoded strings targeting massive userbases (e.g., SBI Yono, PNB, HDFC).

---

## 🔬 Deep Dive: Pipeline Components

### 1. Static Parser (`backend/static_parser.py`)
Utilizes the `androguard` library to tear down the APK without executing it. It extracts the `AndroidManifest.xml`, maps declared permissions against a known threat matrix, and extracts hardcoded IP addresses, domains, and suspicious API calls.

### 2. Semantic Code Slicer (`backend/ai_engine/semantic_analyzer.py`)
Converts the `.dex` Dalvik bytecode into readable Java/Smali representation. It uses AST (Abstract Syntax Tree) heuristics to slice out benign UI code and isolates only the functions related to network, crypto, or file I/O before sending it to the LLM.

### 3. Dynamic Cloud Sandbox (`backend/api/dynamic_sandbox.py`)
Bypasses local resource constraints by interfacing with the VirusTotal API. If a malware author employs anti-sandbox evasion (resulting in a blank behavior report), the pipeline automatically falls back to an AV Reputation aggregator to ensure zero-day threats still receive a high severity score.

### 4. Enterprise PDF Generation (`backend/pdf_generator.py`)
Dynamically synthesizes the findings into an RBI/CERT-In compliant PDF report via ReportLab. Includes a Forensic Narrative, MITRE ATT&CK TTP mapping, Certificate Forensics, and an Incident Response Checklist.

---

## ✨ Key Features & Deliverables

* **Interactive Threat Dashboard**: A React/Vite frontend offering real-time pipeline visualization and D3/Chart.js inspired data rendering.
* **Threat Campaign Attribution Engine**: Uses a Jaccard Similarity Algorithm to instantly match the APK's behavioral indicators against known global cyber syndicates (e.g., Anubis, Cerberus, Jamtara Syndicate).
* **Automated Legal Takedown Generator**: Generates DMCA and CERT-In compliant legal takedown notices against extracted malicious Command & Control (C2) domains with one click.
* **Voice-Enabled Cyber Chatbot**: A built-in Groq-powered AI assistant featuring browser-native Speech-to-Text and Text-to-Speech (English/Hindi) to guide victims through incident response without consuming extra tokens.
* **STIX 2.1 Threat Intel Export**: Seamlessly export IOCs and malware signatures in the globally recognized STIX 2.1 format for automated sharing with SIEMs.
* **Victim-Centric SOS Integration**: Proactive UI alerts instructing victims to contact the **National Cyber Crime Helpline (1930)** and freeze financial assets.

---

## 🛠️ Tech Stack

**Frontend**
* React 18, Vite, TailwindCSS
* Lucide Icons, Axios

**Backend**
* Python 3.10+, FastAPI, Uvicorn
* Androguard (Static Analysis)
* Groq API / OpenAI SDK (GenAI)
* Requests (VirusTotal API Integration)
* ReportLab (PDF Generation)
* Scikit-Learn / XGBoost (ML Models)

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.10 or higher
* Node.js 18.x or higher
* Valid API Keys for Groq and VirusTotal

### 1. Clone the Repository
```bash
git clone https://github.com/SujalDeshmukh/nirikshak-ai.git
cd nirikshak-ai
```

### 2. Backend Setup
Open a terminal in the project root:
```bash
# Install dependencies
pip install -r requirements.txt
pip install cryptography openai

# Set your API keys (Windows PowerShell)
$env:GROQ_API_KEY="your_groq_api_key_here"
$env:VT_API_KEY="your_vt_api_key_here"

# (For Linux/Mac use: export GROQ_API_KEY="...")

# Start the Backend Server
python -m backend.main
```
*The backend will be running at `http://localhost:8001`.*

### 3. Frontend Setup
Open a second terminal in the project root:
```bash
cd frontend

# Install Node modules
npm install

# Start the Development Server
npm run dev
```
*The frontend will be running at `http://localhost:5173`.*

---

## 🌐 API Documentation

Once the backend is running, you can view the auto-generated interactive OpenAPI documentation at:
* **Swagger UI**: `http://localhost:8001/docs`
* **ReDoc**: `http://localhost:8001/redoc`

### Core Endpoints
* `POST /api/v1/analyze`: Upload an APK (`multipart/form-data`) to trigger the 5-stage pipeline.
* `GET /api/v1/download-report`: Stream the resulting PDF investigation report.
* `POST /api/v1/chat`: Converse with the Groq-powered cyber analyst regarding the findings.
* `GET /api/v1/health`: Verify external dependencies (Groq, VT) and model health.

---

## 🔮 Future Roadmap

* **On-Device Federated Learning**: Moving the XGBoost ML model directly to mobile devices for offline zero-day detection.
* **Autonomous Reinforcement Learning**: Deploying RL agents inside the dynamic sandbox to simulate organic human UI interactions to defeat sandbox-evasion malware.
* **Generative AI Threat Simulation**: Utilizing multimodal video-generation models to automatically create a 10-second video simulation of the exact attack vector for executive security training.

---


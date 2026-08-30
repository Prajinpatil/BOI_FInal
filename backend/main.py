# backend/main.py
"""
NIRIKSHAK-AI :: FastAPI Backend Orchestrator
Coordinates the full analysis pipeline:
  APK Upload → Static Parsing → DEX Method Extraction →  Semantic Analysis
  → 5-Factor Risk Fusion → PDF Report Generation → Streaming Download

CORS configured for React development server (ports 5173 and 3000).
"""

import io
import json
import logging
import os
import sys
import tempfile
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

# ─── Logging Configuration ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("nirikshak.api")

# ─── Add project root to sys.path ────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ─── App Initialization ───────────────────────────────────────────────────────
app = FastAPI(
    title="NIRIKSHAK-AI API",
    description=(
        "Automated Mobile Banking Malware Analysis and Risk Scoring Platform. "
        "Provides APK static analysis, semantic LLM threat assessment, "
        "5-factor risk fusion scoring, and RBI-compliant PDF report generation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── CORS Middleware ──────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server (React)
        "http://localhost:3000",   # Create React App / alternative port
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Analysis-ID"],
)

# ─── In-Memory Report Cache ───────────────────────────────────────────────────
# Stores the most recent generated report for download.
# In production, replace with Redis or a persistent store.
_report_cache: dict = {
    "pdf_bytes": None,
    "analysis_data": None,
    "generated_at": None,
    "filename": None,
}

# ─── Pipeline Stage Status (for SSE-style progress tracking) ─────────────────
PIPELINE_STAGES = [
    "upload_received",
    "static_parsing",
    "dex_extraction",
    "semantic_analysis",
    "risk_scoring",
    "pdf_compilation",
    "complete",
]


def _merge_analysis_data(
    static_result: dict,
    semantic_result: dict,
    risk_score_dict: dict,
    apk_filename: str,
) -> dict:
    """
    Merge outputs from all pipeline stages into a single, flat analysis dictionary
    suitable for the API response and PDF generator.
    """
    return {
        # ── File & App Metadata ──
        "filename":              apk_filename,
        "package_name":          static_result.get("package_name", "unknown"),
        "app_name":              static_result.get("app_name") if static_result.get("app_name") not in ["unknown", "", None] else apk_filename,
        "target_sdk":            static_result.get("target_sdk"),
        "min_sdk":               static_result.get("min_sdk"),
        "sha256":                static_result.get("sha256", "unknown"),
        "sha1":                  static_result.get("sha1", "unknown"),
        "file_size_bytes":       static_result.get("file_size_bytes", 0),
        "timestamp":             datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),

        # ── Static Analysis ──
        "permissions":           static_result.get("permissions", []),
        "dangerous_permissions": static_result.get("dangerous_permissions", []),
        "hardcoded_strings":     static_result.get("hardcoded_strings", [])[:50],  # Truncate for API response
        "activities_count":      static_result.get("activities_count", 0),
        "services_count":        static_result.get("services_count", 0),
        "receivers_count":       static_result.get("receivers_count", 0),
        "providers_count":       static_result.get("providers_count", 0),
        "permission_danger_score": static_result.get("permission_danger_score", 0.0),

        # ── Target Detection ──
        "target_detected":       static_result.get("target_detection", {}).get("target_detected", False),
        "matched_targets":       static_result.get("target_detection", {}).get("matched_targets", []),
        "suspicious_patterns":   static_result.get("target_detection", {}).get("suspicious_patterns", []),

        # ── Semantic Analysis ──
        "semantic_score":        semantic_result.get("semantic_score", 0.0),
        "primary_exploit":       semantic_result.get("primary_exploit", "UNKNOWN"),
        "is_indian_vector":      semantic_result.get("is_indian_vector", False),
        "forensic_narrative":    semantic_result.get("forensic_narrative", ""),
        "confidence":            semantic_result.get("confidence", "LOW"),

        # ── Risk Score ──
        "final_score":           risk_score_dict.get("final_score", 0.0),
        "severity_tier":         risk_score_dict.get("severity_tier", "LOW"),
        "severity_color":        risk_score_dict.get("severity_color", "#10B981"),
        "breakdown":             risk_score_dict.get("breakdown", {}),
        "risk_summary":          risk_score_dict.get("risk_summary", ""),
        "recommended_action":    risk_score_dict.get("recommended_action", ""),
        "p_ml_contribution":     risk_score_dict.get("p_ml_contribution", 0.0),
        "semantic_contribution": risk_score_dict.get("semantic_contribution", 0.0),
        "dynamic_contribution":  risk_score_dict.get("dynamic_contribution", 0.0),
        "target_bonus_applied":  risk_score_dict.get("target_bonus_applied", 0.0),
        "iocs":                  static_result.get("iocs", []),
        "cert_analysis":         static_result.get("cert_analysis", {}),
        "mitre_techniques":      static_result.get("mitre_techniques", []),
    }


# ─── Health Check Endpoints ───────────────────────────────────────────────────

@app.get("/", tags=["Status"])
async def root():
    """Root endpoint — service health check."""
    return {
        "service": "NIRIKSHAK-AI",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "analyze":         "POST /api/v1/analyze",
            "download_report": "GET  /api/v1/download-report",
            "health":          "GET  /api/v1/health",
            "docs":            "GET  /docs",
        },
    }


@app.get("/api/v1/health", tags=["Status"])
async def health_check():
    """Detailed health check including Groq AI connectivity."""
    return {
        "status": "online",
        "service": "NIRIKSHAK-AI",
        "ai_provider": "Groq AI",
        "model": "llama-3.3-70b-versatile",
        "ml_model": "XGBoost CICMalDroid",
        "dynamic_sandbox": "VirusTotal Cloud",
        "timestamp": datetime.now().isoformat(),
    }


# ─── Core Analysis Endpoint ───────────────────────────────────────────────────

@app.post("/api/v1/analyze", tags=["Analysis"])
async def analyze_apk(file: UploadFile = File(...)):
    """
    Full APK malware analysis pipeline endpoint.

    Accepts an Android APK file upload and orchestrates:
      1. File validation & SHA-256 hashing
      2. Androguard static analysis
      3. DEX method extraction & AST slicing
      4. Ollama semantic LLM analysis
      5. 5-Factor risk fusion scoring
      6. PDF report compilation

    Returns:
        JSON with complete threat analysis results.
    """
    pipeline_start = time.monotonic()
    stage_timings: dict = {}

    # ── Validate File ─────────────────────────────────────────────────────
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Expected .apk, got: {file.filename}",
        )

    # File size limit: 150MB
    MAX_SIZE = 150 * 1024 * 1024
    apk_content = await file.read()
    if len(apk_content) > MAX_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"APK file too large. Maximum allowed: 150MB. Received: {len(apk_content) / 1024 / 1024:.1f}MB",
        )

    if len(apk_content) < 1024:
        raise HTTPException(
            status_code=400,
            detail="APK file is too small — possibly corrupted or not a valid APK.",
        )

    logger.info("Analysis started: %s (%d bytes)", file.filename, len(apk_content))

    # ── Write to Temp File ────────────────────────────────────────────────
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        tmp.write(apk_content)
        tmp_path = tmp.name

    try:
        # ════════════════════════════════════════════════════════════════
        # STAGE 1: Static Analysis
        # ════════════════════════════════════════════════════════════════
        t0 = time.monotonic()
        logger.info("[Stage 1/5] Starting static analysis...")

        try:
            from backend.static_parser import parse_apk
            static_result = parse_apk(tmp_path)
        except Exception as exc:
            logger.error("Static parser crashed: %s", exc, exc_info=True)
            static_result = {
                "success": False,
                "error": str(exc),
                "package_name": "unknown",
                "app_name": "unknown",
                "target_sdk": None,
                "min_sdk": None,
                "sha256": "error",
                "permissions": [],
                "dangerous_permissions": [],
                "hardcoded_strings": [],
                "target_detection": {"target_detected": False, "matched_targets": [], "suspicious_patterns": []},
                "permission_danger_score": 0.0,
                "file_size_bytes": len(apk_content),
                "activities_count": 0,
                "services_count": 0,
                "receivers_count": 0,
                "providers_count": 0,
            }

        # IOC Extraction
        try:
            from api.ioc_extractor import extract_iocs
            static_result["iocs"] = extract_iocs(static_result.get("hardcoded_strings", []))
        except Exception as exc:
            logger.warning("IOC extraction failed (non-fatal): %s", exc)
            static_result["iocs"] = []

        # Certificate Analysis
        try:
            from api.cert_analyzer import analyze_certificate
            static_result["cert_analysis"] = analyze_certificate(tmp_path)
        except Exception as exc:
            logger.warning("Certificate analysis failed (non-fatal): %s", exc)
            static_result["cert_analysis"] = {}

        # MITRE ATT&CK Mapping
        try:
            from api.mitre_mapper import map_to_mitre
            static_result["mitre_techniques"] = map_to_mitre(
                static_result.get("permissions", []),
                static_result.get("hardcoded_strings", [])
            )
        except Exception as exc:
            logger.warning("MITRE mapping failed (non-fatal): %s", exc)
            static_result["mitre_techniques"] = []

        stage_timings["static_analysis_ms"] = round((time.monotonic() - t0) * 1000, 1)
        logger.info("[Stage 1/5] Complete in %.0fms | pkg=%s | perms=%d",
                    stage_timings["static_analysis_ms"],
                    static_result.get("package_name"),
                    len(static_result.get("permissions", [])))

        # ════════════════════════════════════════════════════════════════
        # STAGE 2: DEX Method Extraction
        # ════════════════════════════════════════════════════════════════
        t0 = time.monotonic()
        logger.info("[Stage 2/5] Extracting DEX methods...")

        decompiled_methods = []
        try:
            from ai_engine.semantic_analyzer import extract_methods_from_dex
            decompiled_methods = extract_methods_from_dex(tmp_path, max_methods=150)
        except Exception as exc:
            logger.warning("DEX method extraction failed (non-fatal): %s", exc)

        stage_timings["dex_extraction_ms"] = round((time.monotonic() - t0) * 1000, 1)
        logger.info("[Stage 2/5] Complete in %.0fms | methods=%d",
                    stage_timings["dex_extraction_ms"], len(decompiled_methods))

        # ════════════════════════════════════════════════════════════════
        # STAGE 3: Semantic LLM Analysis
        # ════════════════════════════════════════════════════════════════
        t0 = time.monotonic()
        logger.info("[Stage 3/5] Running Groq AI semantic analysis...")

        try:
            from ai_engine.semantic_analyzer import analyze_code_semantics
            semantic_result = analyze_code_semantics(decompiled_methods, static_metadata=static_result)
        except Exception as exc:
            logger.error("Semantic analysis failed (using fallback): %s", exc)
            semantic_result = {
                "semantic_score": 0.4,
                "primary_exploit": "UNKNOWN",
                "is_indian_vector": False,
                "forensic_narrative": f"Semantic analysis error: {str(exc)[:200]}",
                "confidence": "LOW",
            }

        stage_timings["semantic_analysis_ms"] = round((time.monotonic() - t0) * 1000, 1)
        logger.info("[Stage 3/5] Complete in %.0fms | score=%.3f | exploit=%s",
                    stage_timings["semantic_analysis_ms"],
                    semantic_result.get("semantic_score", 0),
                    semantic_result.get("primary_exploit"))

        # ════════════════════════════════════════════════════════════════
        # STAGE 4: 5-Factor Risk Fusion Scoring
        # ════════════════════════════════════════════════════════════════
        t0 = time.monotonic()
        logger.info("[Stage 4/5] Computing risk fusion score...")

        try:
            from ai_engine.scoring import build_risk_factors, compute_risk_score, score_to_dict, pml_from_cicmaldroid_features
            
            # Extract features for the ML Model (Permissions + API Calls)
            ml_features = {}
            for perm in static_result.get("permissions", []):
                ml_features[perm.split(".")[-1]] = 1.0
            for method in decompiled_methods:
                m_name = method.get("method_name")
                if m_name:
                    ml_features[m_name] = 1.0
                    
            # Run ML Inference with tolerance for missing features
            ml_result = pml_from_cicmaldroid_features(ml_features, min_coverage=0.0)
            p_ml_val = ml_result.get("PML")
            if p_ml_val is not None:
                logger.info("[Stage 4/5] ML Scanner evaluated features. PML=%.3f", p_ml_val)
            
            # Run Dynamic Sandbox if VT_API_KEY is present
            dynamic_score_val = 0.0
            vt_api_key = os.environ.get("VT_API_KEY")
            if vt_api_key:
                try:
                    from backend.api.dynamic_sandbox import run_cloud_sandbox
                    logger.info("[Stage 4/5] Initiating VirusTotal Dynamic Sandbox...")
                    sha256 = static_result.get("sha256", "unknown")
                    dynamic_score_val = run_cloud_sandbox(tmp_path, sha256, vt_api_key)
                except Exception as exc:
                    logger.error("Failed to run dynamic sandbox: %s", exc)
            else:
                logger.warning("[Stage 4/5] VT_API_KEY is missing! Skipping dynamic sandbox (score defaults to 0.0).")

            factors = build_risk_factors(
                static_result=static_result,
                semantic_result=semantic_result,
                dynamic_score=dynamic_score_val,
                p_ml=p_ml_val
            )
            risk_score = compute_risk_score(factors)
            risk_score_dict = score_to_dict(risk_score)
        except Exception as exc:
            logger.error("Risk scoring failed (using minimal fallback): %s", exc)
            risk_score_dict = {
                "final_score": 50.0,
                "severity_tier": "MEDIUM",
                "severity_color": "#EAB308",
                "breakdown": {},
                "risk_summary": "Scoring error — manual review required.",
                "recommended_action": "Conduct manual forensic review.",
                "p_ml_contribution": 0.0,
                "semantic_contribution": 0.0,
                "dynamic_contribution": 0.0,
                "target_bonus_applied": 0.0,
            }

        stage_timings["risk_scoring_ms"] = round((time.monotonic() - t0) * 1000, 1)
        logger.info("[Stage 4/5] Complete in %.0fms | score=%.1f | tier=%s",
                    stage_timings["risk_scoring_ms"],
                    risk_score_dict.get("final_score"),
                    risk_score_dict.get("severity_tier"))

        # ════════════════════════════════════════════════════════════════
        # STAGE 5: PDF Compilation
        # ════════════════════════════════════════════════════════════════
        t0 = time.monotonic()
        logger.info("[Stage 5/5] Generating PDF report...")

        analysis_data = _merge_analysis_data(
            static_result, semantic_result, risk_score_dict, file.filename
        )

        try:
            from backend.pdf_generator import generate_pdf_report
            pdf_bytes = generate_pdf_report(analysis_data)
            pdf_filename = (
                f"NIRIKSHAK_Report_{analysis_data['package_name'].replace('.', '_')}"
                f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )

            # Cache for download endpoint
            _report_cache["pdf_bytes"] = pdf_bytes
            _report_cache["analysis_data"] = analysis_data
            _report_cache["generated_at"] = datetime.now().isoformat()
            _report_cache["filename"] = pdf_filename

        except Exception as exc:
            logger.error("PDF generation failed (non-fatal): %s", exc, exc_info=True)
            pdf_bytes = None
            pdf_filename = None

        stage_timings["pdf_generation_ms"] = round((time.monotonic() - t0) * 1000, 1)
        logger.info("[Stage 5/5] Complete in %.0fms | pdf_size=%s",
                    stage_timings["pdf_generation_ms"],
                    f"{len(pdf_bytes)} bytes" if pdf_bytes else "FAILED")

    finally:
        # Always clean up temp file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    # ── Build Response ────────────────────────────────────────────────────
    total_ms = round((time.monotonic() - pipeline_start) * 1000, 1)
    logger.info(
        "Analysis pipeline complete: %s | score=%.1f | tier=%s | total=%.0fms",
        file.filename,
        analysis_data.get("final_score", 0),
        analysis_data.get("severity_tier", "?"),
        total_ms,
    )

    return JSONResponse(
        content={
            "success": True,
            "analysis": analysis_data,
            "pipeline_timings": {
                **stage_timings,
                "total_ms": total_ms,
            },
            "report_ready": pdf_bytes is not None,
            "report_filename": pdf_filename,
        },
        headers={
            "X-Analysis-ID": f"{analysis_data.get('sha256', 'unknown')[:16]}",
            "X-Severity-Tier": analysis_data.get("severity_tier", "UNKNOWN"),
        },
    )


# ─── PDF Download Endpoint ────────────────────────────────────────────────────

@app.get("/api/v1/download-report", tags=["Reports"])
async def download_report():
    """
    Stream the most recently generated PDF threat report to the client.
    The report is cached in memory after the /api/v1/analyze call completes.
    """
    if _report_cache["pdf_bytes"] is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No report available for download. "
                "Please submit an APK via POST /api/v1/analyze first."
            ),
        )

    pdf_bytes = _report_cache["pdf_bytes"]
    filename = _report_cache.get("filename", "NIRIKSHAK_Report.pdf")

    def iter_pdf():
        yield pdf_bytes

    return StreamingResponse(
        iter_pdf(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "X-Report-Generated": _report_cache.get("generated_at", ""),
        },
    )


@app.get("/api/v1/report-status", tags=["Reports"])
async def report_status():
    """Check if a report is available for download."""
    return {
        "report_available": _report_cache["pdf_bytes"] is not None,
        "generated_at": _report_cache.get("generated_at"),
        "filename": _report_cache.get("filename"),
        "size_bytes": len(_report_cache["pdf_bytes"]) if _report_cache["pdf_bytes"] else 0,
    }


# ─── Groq AI Security Chatbot Endpoint ────────────────────────────────────────

@app.post("/api/v1/chat", tags=["AI"])
async def chat(request: Request):
    """
    Groq AI security chatbot endpoint.
    Accepts messages list and optional system prompt, returns AI response.
    """
    try:
        body = await request.json()
        messages = body.get("messages", [])
        system_prompt = body.get("system", "You are a helpful cybersecurity assistant.")

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            return JSONResponse(
                status_code=503,
                content={"reply": "⚠️ AI assistant is offline (GROQ_API_KEY not set). Please call 1930 for immediate cyber crime support."}
            )

        try:
            from openai import OpenAI
        except ImportError:
            return JSONResponse(
                status_code=503,
                content={"reply": "⚠️ AI library not available. Please call 1930 for immediate cyber crime support."}
            )

        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
        groq_messages = [{"role": "system", "content": system_prompt}] + [
            {"role": m["role"], "content": m["content"]}
            for m in messages[-10:]  # Keep last 10 messages for context
        ]

        # ── Dynamic model discovery ────────────────────────────────────────
        # Query Groq's live model list so we never hardcode a retired model.
        # Prefer large/versatile models; fall back to any available chat model.
        PREFERRED_KEYWORDS = ["llama", "compound", "qwen", "deepseek", "gemma", "mistral"]
        SKIP_KEYWORDS = ["whisper", "tts", "guard", "vision", "preview"]

        try:
            models_response = client.models.list()
            available = [
                m.id for m in models_response.data
                if not any(s in m.id.lower() for s in SKIP_KEYWORDS)
            ]
            # Sort: prefer models whose names contain preferred keywords
            def score_model(mid):
                mid_lower = mid.lower()
                for i, kw in enumerate(PREFERRED_KEYWORDS):
                    if kw in mid_lower:
                        # Within each keyword group, prefer larger models (70b > 8b)
                        size = 0
                        if "70b" in mid_lower: size = 70
                        elif "32b" in mid_lower: size = 32
                        elif "13b" in mid_lower: size = 13
                        elif "8b" in mid_lower: size = 8
                        elif "7b" in mid_lower: size = 7
                        return (i, -size)
                return (len(PREFERRED_KEYWORDS), 0)

            available.sort(key=score_model)
            logger.info("Groq available models: %s", available[:5])
        except Exception as list_err:
            logger.warning("Could not list Groq models: %s — using built-in fallback", list_err)
            available = ["llama-3.3-70b-specdec", "llama-3.1-8b-instant",
                         "compound-beta", "compound-beta-mini"]

        if not available:
            return JSONResponse(
                status_code=503,
                content={"reply": "⚠️ No AI models available on Groq right now. Please call 1930 for immediate cyber crime support."}
            )

        reply = None
        last_error = None
        for model_name in available[:5]:  # Try top 5 candidates
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=groq_messages,
                    max_tokens=300,
                    temperature=0.6,
                )
                reply = response.choices[0].message.content
                logger.info("Groq chat success using model: %s", model_name)
                break
            except Exception as model_err:
                logger.warning("Groq model %s failed: %s — trying next...", model_name, model_err)
                last_error = model_err
                continue

        if not reply:
            raise last_error

        return {"reply": reply}

    except Exception as exc:
        logger.error("Chat endpoint error: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"reply": "⚠️ I encountered an error. For immediate help: Call 1930 or visit cybercrime.gov.in"}
        )

# ─── Global Exception Handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception at %s: %s\n%s",
                 request.url, exc, traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "detail": str(exc)[:300],
            "path": str(request.url),
        },
    )


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         NIRIKSHAK-AI :: Backend API Server               ║")
    print("║  Mobile Banking Malware Analysis Platform v1.0.0         ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print("  API:  http://localhost:8001")
    print("  Docs: http://localhost:8001/docs")
    print()

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
        workers=1,
    )

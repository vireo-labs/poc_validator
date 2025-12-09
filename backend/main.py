"""
PoC Validator API v2
FastAPI application with batch Snyk validation support.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import json
from datetime import datetime
import asyncio
import uuid

from database import engine, Base, SessionLocal
from models import VulnerabilityReport, ValidationResult, ValidationStatus, VerdictType

# Import agents
from agents.report_parser import report_parser
from agents.code_analyzer import code_analyzer
from agents.poc_discoverer import poc_discoverer
from agents.sandbox_executor import sandbox_executor
from agents.llm_judge import llm_judge

# Import pipeline
from services.pipeline import PipelineOrchestrator

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PoC Validator",
    description="Automatically validate security vulnerabilities by running exploits in sandboxes",
    version="0.2.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class SubmitReportRequest(BaseModel):
    title: str
    description: str
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None
    affected_file: Optional[str] = None
    source: Optional[str] = "manual"
    repo_url: Optional[str] = "https://github.com/varun2117/juice-shop"


class ValidationResponse(BaseModel):
    id: int
    status: str
    verdict: Optional[str] = None
    message: str


class ValidationStatusResponse(BaseModel):
    id: int
    status: str
    verdict: Optional[str] = None
    parsed_data: Optional[dict] = None
    code_analysis: Optional[dict] = None
    exploit_name: Optional[str] = None
    execution_output: Optional[dict] = None
    judge_reasoning: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class BatchJobResponse(BaseModel):
    job_id: str
    status: str
    total_alerts: int
    unique_vulnerabilities: int
    message: str


class BatchResultResponse(BaseModel):
    job_id: str
    status: str
    progress: dict
    summary: Optional[dict] = None
    results: Optional[List[dict]] = None


# In-memory stores
validations = {}
batch_jobs = {}


async def run_validation_pipeline(validation_id: int, report_content: str, source: str, repo_url: str):
    """Run the full 5-agent validation pipeline for single vulnerability."""
    db = SessionLocal()
    
    try:
        def update_status(status: ValidationStatus, **kwargs):
            validations[validation_id]["status"] = status.value
            validations[validation_id].update(kwargs)
        
        # Agent 1: Parse Report
        update_status(ValidationStatus.PARSING)
        parsed = await report_parser.parse(report_content, source)
        
        if not parsed["success"]:
            update_status(ValidationStatus.FAILED, error=parsed.get("error"))
            return
        
        validations[validation_id]["parsed_data"] = parsed["data"]
        
        # Agent 2: Analyze Code
        update_status(ValidationStatus.ANALYZING)
        analysis = await code_analyzer.analyze(parsed["data"], repo_url)
        
        if not analysis["success"]:
            update_status(ValidationStatus.FAILED, error=analysis.get("error"))
            return
        
        validations[validation_id]["code_analysis"] = analysis["data"]
        
        # Check if auto-exploitable
        classification = analysis.get("classification", {})
        can_auto_exploit = classification.get("can_auto_exploit", True)
        
        if not can_auto_exploit:
            if analysis["data"].get("vulnerable_code_exists"):
                update_status(
                    ValidationStatus.COMPLETED,
                    verdict=VerdictType.CODE_VERIFIED.value,
                    judge_reasoning=f"Vulnerability pattern confirmed in source code. {analysis['data'].get('explanation', '')}",
                    completed_at=datetime.now().isoformat()
                )
            else:
                update_status(
                    ValidationStatus.COMPLETED,
                    verdict=VerdictType.NEEDS_REVIEW.value,
                    judge_reasoning="Could not confirm vulnerability pattern. Manual review recommended.",
                    completed_at=datetime.now().isoformat()
                )
            return
        
        # Agent 3: Discover PoC
        update_status(ValidationStatus.DISCOVERING)
        poc = await poc_discoverer.discover(parsed["data"], analysis)
        
        if not poc["success"]:
            update_status(ValidationStatus.FAILED, error=poc.get("error"))
            return
        
        validations[validation_id]["exploit_name"] = poc["exploit_name"]
        
        # Agent 4: Execute in Sandbox
        update_status(ValidationStatus.EXECUTING)
        execution = await sandbox_executor.execute(
            poc["exploit_code"], 
            poc["exploit_name"],
            language=poc.get("language", "python")
        )
        
        validations[validation_id]["execution_output"] = {
            "stdout": execution.get("stdout", ""),
            "stderr": execution.get("stderr", ""),
            "exit_code": execution.get("exit_code"),
            "duration_ms": execution.get("duration_ms"),
            "exploit_succeeded": execution.get("exploit_succeeded", False)
        }
        
        # Agent 5: Judge Results
        update_status(ValidationStatus.JUDGING)
        judgment = await llm_judge.judge(parsed["data"], analysis, execution)
        
        if judgment["success"]:
            update_status(
                ValidationStatus.COMPLETED,
                verdict=judgment["verdict"],
                judge_reasoning=judgment.get("reasoning"),
                completed_at=datetime.now().isoformat()
            )
        else:
            update_status(ValidationStatus.FAILED, error=judgment.get("error"))
            
    except Exception as e:
        validations[validation_id]["status"] = ValidationStatus.FAILED.value
        validations[validation_id]["error"] = str(e)
    finally:
        db.close()


async def run_batch_validation(job_id: str, snyk_data: dict, project_path: str):
    """Run validation pipeline for all vulnerabilities in Snyk report."""
    try:
        batch_jobs[job_id]["status"] = "running"
        batch_jobs[job_id]["started_at"] = datetime.now().isoformat()
        batch_jobs[job_id]["progress"] = {
            "current": 0,
            "total": 0,
            "current_package": None,
            "completed": []
        }
        
        # Initialize orchestrator
        orchestrator = PipelineOrchestrator(project_path=project_path)
        
        # Progress callback to update job status
        def on_progress(current, total, package, verdict, reason):
            batch_jobs[job_id]["progress"] = {
                "current": current,
                "total": total,
                "current_package": package,
                "completed": batch_jobs[job_id]["progress"].get("completed", []) + [{
                    "package": package,
                    "verdict": verdict,
                    "reason": reason[:80]
                }]
            }
        
        # Run validation with progress tracking
        results = await orchestrator.validate(snyk_data, progress_callback=on_progress)
        
        # Update job with results
        batch_jobs[job_id]["status"] = "completed"
        batch_jobs[job_id]["completed_at"] = datetime.now().isoformat()
        batch_jobs[job_id]["summary"] = {
            "total_scanned": results["total_scanned"],
            "unique_validated": results["unique_validated"],
            "exploitable_count": results["exploitable_count"],
            "by_verdict": results["by_verdict"]
        }
        batch_jobs[job_id]["results"] = results["results"]
        batch_jobs[job_id]["exploitable"] = results["exploitable"]
        
    except Exception as e:
        batch_jobs[job_id]["status"] = "failed"
        batch_jobs[job_id]["error"] = str(e)



@app.get("/")
async def root():
    return {
        "name": "PoC Validator API",
        "version": "0.2.0",
        "status": "running",
        "endpoints": {
            "single": "/api/validate",
            "batch": "/api/batch/validate",
            "health": "/health"
        }
    }


# ============================================================================
# SINGLE VULNERABILITY VALIDATION
# ============================================================================

@app.post("/api/validate", response_model=ValidationResponse)
async def submit_validation(request: SubmitReportRequest, background_tasks: BackgroundTasks):
    """Submit a single vulnerability for validation."""
    
    validation_id = len(validations) + 1
    
    report_content = f"""
Title: {request.title}
Description: {request.description}
Vulnerability Type: {request.vulnerability_type or 'Unknown'}
Severity: {request.severity or 'Unknown'}
Affected File: {request.affected_file or 'Unknown'}
"""
    
    validations[validation_id] = {
        "id": validation_id,
        "status": ValidationStatus.PENDING.value,
        "verdict": None,
        "report": request.dict(),
        "started_at": datetime.now().isoformat()
    }
    
    background_tasks.add_task(
        run_validation_pipeline,
        validation_id,
        report_content,
        request.source,
        request.repo_url
    )
    
    return ValidationResponse(
        id=validation_id,
        status=ValidationStatus.PENDING.value,
        message="Validation started. Poll /api/validate/{id} for status."
    )


@app.get("/api/validate/{validation_id}", response_model=ValidationStatusResponse)
async def get_validation_status(validation_id: int):
    """Get the status and results of a single validation."""
    
    if validation_id not in validations:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    v = validations[validation_id]
    
    return ValidationStatusResponse(
        id=validation_id,
        status=v.get("status"),
        verdict=v.get("verdict"),
        parsed_data=v.get("parsed_data"),
        code_analysis=v.get("code_analysis"),
        exploit_name=v.get("exploit_name"),
        execution_output=v.get("execution_output"),
        judge_reasoning=v.get("judge_reasoning"),
        started_at=v.get("started_at"),
        completed_at=v.get("completed_at")
    )


@app.get("/api/validations")
async def list_validations():
    """List all single validations."""
    return {
        "validations": [
            {
                "id": v["id"],
                "status": v["status"],
                "verdict": v.get("verdict"),
                "title": v.get("report", {}).get("title", "Unknown")
            }
            for v in validations.values()
        ]
    }


# ============================================================================
# BATCH SNYK VALIDATION
# ============================================================================

@app.post("/api/batch/validate", response_model=BatchJobResponse)
async def submit_batch_validation(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_path: str = Form(default="")
):
    """
    Submit a Snyk JSON report for batch validation.
    
    - **file**: Snyk JSON export file
    - **project_path**: Optional path to project with node_modules (for dependency exploits)
    """
    
    # Validate file type
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="File must be a JSON file")
    
    # Read and parse JSON
    try:
        content = await file.read()
        snyk_data = json.loads(content.decode('utf-8'))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    
    # Count vulnerabilities
    vulnerabilities = snyk_data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise HTTPException(status_code=400, detail="No vulnerabilities found in Snyk report")
    
    # Create job
    job_id = str(uuid.uuid4())[:8]
    
    # Deduplicate by package name
    unique_packages = set()
    for v in vulnerabilities:
        pkg = v.get("packageName", v.get("name", "unknown"))
        unique_packages.add(pkg)
    
    batch_jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "total_alerts": len(vulnerabilities),
        "unique_vulnerabilities": len(unique_packages),
        "project_path": project_path,
        "created_at": datetime.now().isoformat(),
        "progress": {
            "completed": 0,
            "total": len(unique_packages),
            "current_package": None
        }
    }
    
    # Start background validation
    background_tasks.add_task(
        run_batch_validation,
        job_id,
        snyk_data,
        project_path
    )
    
    return BatchJobResponse(
        job_id=job_id,
        status="pending",
        total_alerts=len(vulnerabilities),
        unique_vulnerabilities=len(unique_packages),
        message=f"Batch validation started. Poll /api/batch/{job_id} for status."
    )


@app.get("/api/batch/{job_id}")
async def get_batch_status(job_id: str):
    """Get the status and results of a batch validation job."""
    
    if job_id not in batch_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = batch_jobs[job_id]
    
    response = {
        "job_id": job_id,
        "status": job["status"],
        "total_alerts": job["total_alerts"],
        "unique_vulnerabilities": job["unique_vulnerabilities"],
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at")
    }
    
    if job["status"] == "completed":
        response["summary"] = job.get("summary", {})
        response["exploitable"] = job.get("exploitable", [])
        response["results"] = job.get("results", [])
    elif job["status"] == "failed":
        response["error"] = job.get("error")
    
    return response


@app.get("/api/batch")
async def list_batch_jobs():
    """List all batch validation jobs."""
    return {
        "jobs": [
            {
                "job_id": j["job_id"],
                "status": j["status"],
                "total_alerts": j["total_alerts"],
                "unique_vulnerabilities": j["unique_vulnerabilities"],
                "created_at": j.get("created_at"),
                "completed_at": j.get("completed_at")
            }
            for j in batch_jobs.values()
        ]
    }


@app.delete("/api/batch/{job_id}")
async def delete_batch_job(job_id: str):
    """Delete a batch validation job."""
    if job_id not in batch_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    del batch_jobs[job_id]
    return {"message": "Job deleted"}


# ============================================================================
# HEALTH & UTILITIES
# ============================================================================

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "0.2.0"}


@app.delete("/api/validate/{validation_id}")
async def delete_validation(validation_id: int):
    """Delete a validation record."""
    if validation_id not in validations:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    del validations[validation_id]
    return {"message": "Validation deleted"}

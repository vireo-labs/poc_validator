"""
PoC Validator API
FastAPI application for validating security vulnerabilities.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import json
from datetime import datetime

from database import engine, Base, SessionLocal
from models import VulnerabilityReport, ValidationResult, ValidationStatus, VerdictType

# Import agents
from agents.report_parser import report_parser
from agents.code_analyzer import code_analyzer
from agents.poc_discoverer import poc_discoverer
from agents.sandbox_executor import sandbox_executor
from agents.llm_judge import llm_judge

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="PoC Validator",
    description="Automatically validate security vulnerabilities by running exploits in sandboxes",
    version="0.1.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
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


# In-memory store for demo (will use DB in production)
validations = {}


async def run_validation_pipeline(validation_id: int, report_content: str, source: str, repo_url: str):
    """Run the full 5-agent validation pipeline."""
    db = SessionLocal()
    
    try:
        # Update status helper
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
        
        # Agent 2: Analyze Code (clones repo and searches actual code)
        update_status(ValidationStatus.ANALYZING)
        analysis = await code_analyzer.analyze(parsed["data"], repo_url)
        
        if not analysis["success"]:
            update_status(ValidationStatus.FAILED, error=analysis.get("error"))
            return
        
        validations[validation_id]["code_analysis"] = analysis["data"]
        
        # Agent 3: Discover PoC
        update_status(ValidationStatus.DISCOVERING)
        poc = await poc_discoverer.discover(parsed["data"], analysis)
        
        if not poc["success"]:
            update_status(ValidationStatus.FAILED, error=poc.get("error"))
            return
        
        validations[validation_id]["exploit_name"] = poc["exploit_name"]
        validations[validation_id]["exploit_code"] = poc["exploit_code"]
        
        # Agent 4: Execute in Sandbox
        update_status(ValidationStatus.EXECUTING)
        execution = await sandbox_executor.execute(poc["exploit_code"], poc["exploit_name"])
        
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
                evidence=judgment.get("evidence", []),
                recommendations=judgment.get("recommendations", []),
                completed_at=datetime.now().isoformat()
            )
        else:
            update_status(ValidationStatus.FAILED, error=judgment.get("error"))
            
    except Exception as e:
        validations[validation_id]["status"] = ValidationStatus.FAILED.value
        validations[validation_id]["error"] = str(e)
    finally:
        db.close()


@app.get("/")
async def root():
    return {
        "name": "PoC Validator API",
        "version": "0.1.0",
        "status": "running"
    }


@app.post("/api/validate", response_model=ValidationResponse)
async def submit_validation(request: SubmitReportRequest, background_tasks: BackgroundTasks):
    """Submit a vulnerability report for validation."""
    
    # Create validation record
    validation_id = len(validations) + 1
    
    # Build report content
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
    
    # Store repo URL
    validations[validation_id]["repo_url"] = request.repo_url
    
    # Start validation pipeline in background
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
    """Get the status and results of a validation."""
    
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
    """List all validations."""
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


@app.delete("/api/validate/{validation_id}")
async def delete_validation(validation_id: int):
    """Delete a validation record."""
    if validation_id not in validations:
        raise HTTPException(status_code=404, detail="Validation not found")
    
    del validations[validation_id]
    return {"message": "Validation deleted"}


# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

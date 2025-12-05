from sqlalchemy import Column, Integer, String, Text, DateTime, Enum as SQLEnum
from sqlalchemy.sql import func
from database import Base
import enum


class VerdictType(str, enum.Enum):
    VALID = "VALID"                    # Exploit executed successfully
    INVALID = "INVALID"                # Exploit failed - vuln doesn't exist
    CODE_VERIFIED = "CODE_VERIFIED"    # Code pattern confirmed (no execution needed)
    NEEDS_REVIEW = "NEEDS_REVIEW"      # Inconclusive - manual review needed
    PENDING = "PENDING"


class ValidationStatus(str, enum.Enum):
    PENDING = "PENDING"
    PARSING = "PARSING"
    ANALYZING = "ANALYZING"
    DISCOVERING = "DISCOVERING"
    EXECUTING = "EXECUTING"
    JUDGING = "JUDGING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VulnerabilityReport(Base):
    __tablename__ = "vulnerability_reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(50))  # CRITICAL, HIGH, MEDIUM, LOW
    vulnerability_type = Column(String(100))  # SQLi, XSS, RCE, etc.
    affected_file = Column(String(500))
    affected_line = Column(Integer)
    source = Column(String(100))  # Scanner name: Snyk, Semgrep, etc.
    raw_report = Column(Text)  # Original report content
    created_at = Column(DateTime, server_default=func.now())


class ValidationResult(Base):
    __tablename__ = "validation_results"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, nullable=False)
    status = Column(SQLEnum(ValidationStatus), default=ValidationStatus.PENDING)
    verdict = Column(SQLEnum(VerdictType), default=VerdictType.PENDING)
    
    # Agent outputs
    parsed_data = Column(Text)  # JSON from Report Parser
    code_analysis = Column(Text)  # JSON from Code Analyzer
    poc_script = Column(Text)  # Exploit code from PoC Discoverer
    execution_output = Column(Text)  # Output from Sandbox Executor
    judge_reasoning = Column(Text)  # LLM Judge explanation
    
    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())


class ExploitRun(Base):
    __tablename__ = "exploit_runs"

    id = Column(Integer, primary_key=True, index=True)
    validation_id = Column(Integer, nullable=False)
    exploit_name = Column(String(255))
    container_id = Column(String(100))
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    duration_ms = Column(Integer)
    created_at = Column(DateTime, server_default=func.now())

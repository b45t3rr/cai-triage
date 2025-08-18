#!/usr/bin/env python3
"""
Entidades de dominio para el sistema de análisis de vulnerabilidades

Este módulo contiene las entidades principales del dominio:
- Vulnerability: Representa una vulnerabilidad encontrada
- Report: Representa un reporte de seguridad
- Analysis: Representa un análisis realizado por un agente
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from uuid import uuid4


class SeverityLevel(Enum):
    """Niveles de severidad de vulnerabilidades"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Priority(Enum):
    """Prioridades de vulnerabilidades"""
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class ConfidenceLevel(Enum):
    """Niveles de confianza en el análisis"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnerabilityStatus(Enum):
    """Estados de vulnerabilidad"""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN = "unknown"


class AnalysisType(Enum):
    """Tipos de análisis"""
    REPORT_READING = "report_reading"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    TRIAGE = "triage"


@dataclass
class Vulnerability:
    """Entidad que representa una vulnerabilidad"""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    vulnerability_type: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.LOW
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    priority: Optional[Priority] = None
    
    # Ubicación en el código
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    # Evidencia y análisis
    evidence: List[str] = field(default_factory=list)
    exploitation_steps: str = ""
    impact: str = ""
    remediation: str = ""
    mitigation_recommendations: List[str] = field(default_factory=list)
    
    # Referencias técnicas
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Metadatos
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    sources: List[str] = field(default_factory=list)
    report_id: Optional[str] = None
    
    def update_severity(self, new_severity: SeverityLevel) -> None:
        """Actualiza la severidad si es mayor que la actual"""
        severity_order = {
            SeverityLevel.INFO: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        
        if severity_order[new_severity] > severity_order[self.severity]:
            self.severity = new_severity
            self.updated_at = datetime.utcnow()
    
    def add_evidence(self, evidence: str, source: str) -> None:
        """Añade evidencia de una fuente específica"""
        if evidence not in self.evidence:
            self.evidence.append(evidence)
        if source not in self.sources:
            self.sources.append(source)
        self.updated_at = datetime.utcnow()
    
    def calculate_priority(self) -> Priority:
        """Calcula la prioridad basada en severidad, confianza y evidencia"""
        has_exploit = bool(self.exploitation_steps)
        
        if self.severity == SeverityLevel.CRITICAL and self.confidence == ConfidenceLevel.HIGH:
            return Priority.P0
        elif self.severity == SeverityLevel.HIGH and (self.confidence == ConfidenceLevel.HIGH or has_exploit):
            return Priority.P1
        elif self.severity == SeverityLevel.MEDIUM:
            return Priority.P2
        else:
            return Priority.P3


@dataclass
class Report:
    """Entidad que representa un reporte de seguridad"""
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    file_path: str = ""
    client: str = ""
    consultant: str = ""
    version: str = ""
    
    # Scope del penetration test
    targets: List[str] = field(default_factory=list)
    applications: List[str] = field(default_factory=list)
    limitations: str = ""
    
    # Credenciales y accesos
    test_accounts: Dict[str, str] = field(default_factory=dict)
    access_levels: List[str] = field(default_factory=list)
    
    # Metodología
    tools_used: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    standards: List[str] = field(default_factory=list)
    
    # Resumen ejecutivo
    key_findings: List[str] = field(default_factory=list)
    general_recommendations: List[str] = field(default_factory=list)
    
    # Metadatos
    created_at: datetime = field(default_factory=datetime.utcnow)
    report_date: Optional[datetime] = None
    processed_at: Optional[datetime] = None


@dataclass
class Analysis:
    """Entidad que representa un análisis realizado por un agente"""
    analysis_type: AnalysisType
    agent_name: str
    id: str = field(default_factory=lambda: str(uuid4()))
    
    # Referencias
    report_id: Optional[str] = None
    vulnerability_id: Optional[str] = None  # ID de la vulnerabilidad específica analizada
    vulnerability_ids: List[str] = field(default_factory=list)  # Para análisis de múltiples vulnerabilidades
    
    # Configuración del análisis
    source_directory: Optional[str] = None
    target_host: Optional[str] = None
    model_used: str = "gpt-5-nano"
    
    # Resultados del análisis específico
    status: str = "pending"  # pending, running, completed, failed, vulnerable, not_vulnerable
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    evidence: List[str] = field(default_factory=list)
    analysis_summary: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    # Resultados agregados (para análisis de múltiples vulnerabilidades)
    vulnerabilities_found: int = 0
    vulnerabilities_validated: int = 0
    total_requests_made: int = 0
    
    # Metadatos
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time_seconds: Optional[float] = None
    
    # Contexto adicional
    context: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def start_analysis(self) -> None:
        """Marca el análisis como iniciado"""
        self.status = "running"
        self.started_at = datetime.utcnow()
    
    def complete_analysis(self, vulnerabilities_found: int = 0, vulnerabilities_validated: int = 0) -> None:
        """Marca el análisis como completado"""
        self.status = "completed"
        self.completed_at = datetime.utcnow()
        self.vulnerabilities_found = vulnerabilities_found
        self.vulnerabilities_validated = vulnerabilities_validated
        
        if self.started_at:
            self.execution_time_seconds = (self.completed_at - self.started_at).total_seconds()
    
    def fail_analysis(self, error_message: str) -> None:
        """Marca el análisis como fallido"""
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        self.error_message = error_message
        
        if self.started_at:
            self.execution_time_seconds = (self.completed_at - self.started_at).total_seconds()


@dataclass
class TriageResult:
    """Entidad que representa el resultado consolidado del triage"""
    # Referencias
    report_id: str
    id: str = field(default_factory=lambda: str(uuid4()))
    analysis_ids: List[str] = field(default_factory=list)
    
    # Resumen del triage
    total_vulnerabilities_before_deduplication: int = 0
    total_unique_vulnerabilities: int = 0
    sources_processed: int = 0
    source_files: List[str] = field(default_factory=list)
    
    # Distribución por severidad
    vulnerabilities_by_severity: Dict[str, int] = field(default_factory=dict)
    
    # Vulnerabilidades consolidadas
    consolidated_vulnerability_ids: List[str] = field(default_factory=list)
    
    # Resumen estructurado del triage (para compatibilidad con app.py)
    triage_summary: Dict[str, Any] = field(default_factory=dict)
    
    # Metadatos
    created_at: datetime = field(default_factory=datetime.utcnow)
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    analysis_completed_at: datetime = field(default_factory=datetime.utcnow)
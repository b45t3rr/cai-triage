#!/usr/bin/env python3
"""
Implementaciones de repositorios usando MongoDB

Este módulo contiene las implementaciones concretas de los repositorios
usando MongoDB como base de datos.
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from ..domain.entities import (
    Vulnerability, Report, Analysis, TriageResult,
    SeverityLevel, Priority, ConfidenceLevel, VulnerabilityStatus, AnalysisType
)
from ..domain.repositories import (
    VulnerabilityRepository, ReportRepository, AnalysisRepository, TriageResultRepository
)

logger = logging.getLogger(__name__)


class MongoDBVulnerabilityRepository(VulnerabilityRepository):
    """Implementación MongoDB del repositorio de vulnerabilidades"""
    
    def __init__(self, database: Database):
        self.collection: Collection = database.vulnerabilities
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        """Crea índices necesarios para optimizar consultas"""
        try:
            self.collection.create_index("report_id")
            self.collection.create_index("severity")
            self.collection.create_index("status")
            self.collection.create_index("priority")
            self.collection.create_index("created_at")
            self.collection.create_index([("name", "text"), ("description", "text")])
        except Exception as e:
            logger.warning(f"Error creating indexes: {e}")
    
    async def save(self, vulnerability: Vulnerability) -> str:
        """Guarda una vulnerabilidad en MongoDB"""
        doc = self._to_document(vulnerability)
        
        if vulnerability.id:
            # Actualizar existente
            result = self.collection.replace_one(
                {"_id": vulnerability.id},
                doc,
                upsert=True
            )
            return vulnerability.id
        else:
            # Crear nuevo
            result = self.collection.insert_one(doc)
            return str(result.inserted_id)
    
    async def find_by_id(self, vulnerability_id: str) -> Optional[Vulnerability]:
        """Busca una vulnerabilidad por ID"""
        try:
            doc = self.collection.find_one({"_id": vulnerability_id})
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding vulnerability by ID {vulnerability_id}: {e}")
            return None
    
    async def find_by_report_id(self, report_id: str) -> List[Vulnerability]:
        """Busca vulnerabilidades por ID de reporte"""
        try:
            docs = self.collection.find({"report_id": report_id})
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding vulnerabilities by report ID {report_id}: {e}")
            return []
    
    async def find_by_severity(self, severity: SeverityLevel) -> List[Vulnerability]:
        """Busca vulnerabilidades por severidad"""
        try:
            docs = self.collection.find({"severity": severity.value})
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding vulnerabilities by severity {severity}: {e}")
            return []
    
    async def find_by_status(self, status: VulnerabilityStatus) -> List[Vulnerability]:
        """Busca vulnerabilidades por estado"""
        try:
            docs = self.collection.find({"status": status.value})
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding vulnerabilities by status {status}: {e}")
            return []
    
    async def update(self, vulnerability: Vulnerability) -> bool:
        """Actualiza una vulnerabilidad"""
        if not vulnerability.id:
            return False
        
        try:
            vulnerability.updated_at = datetime.utcnow()
            doc = self._to_document(vulnerability)
            result = self.collection.replace_one(
                {"_id": vulnerability.id},
                doc
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating vulnerability {vulnerability.id}: {e}")
            return False
    
    async def delete(self, vulnerability_id: str) -> bool:
        """Elimina una vulnerabilidad"""
        try:
            result = self.collection.delete_one({"_id": vulnerability_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting vulnerability {vulnerability_id}: {e}")
            return False
    
    async def count_by_severity(self, report_id: str) -> Dict[SeverityLevel, int]:
        """Cuenta vulnerabilidades por severidad en un reporte"""
        try:
            pipeline = [
                {"$match": {"report_id": report_id}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
            ]
            
            results = list(self.collection.aggregate(pipeline))
            counts = {severity: 0 for severity in SeverityLevel}
            
            for result in results:
                try:
                    severity = SeverityLevel(result["_id"])
                    counts[severity] = result["count"]
                except ValueError:
                    continue
            
            return counts
        except Exception as e:
            logger.error(f"Error counting vulnerabilities by severity: {e}")
            return {severity: 0 for severity in SeverityLevel}

    async def find_by_name_and_type(self, name: str, vulnerability_type: str) -> List[Vulnerability]:
        """Busca vulnerabilidades por nombre y tipo (para deduplicación)"""
        try:
            docs = list(self.collection.find({
                "name": name,
                "vulnerability_type": vulnerability_type
            }))
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding vulnerabilities by name and type: {e}")
            return []

    async def find_all(self, limit: int = 100, offset: int = 0) -> List[Vulnerability]:
        """Obtiene todas las vulnerabilidades con paginación"""
        try:
            docs = list(self.collection.find().skip(offset).limit(limit))
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding all vulnerabilities: {e}")
            return []

    def _to_document(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Convierte una vulnerabilidad a documento MongoDB"""
        doc = {
            "name": vulnerability.name,
            "vulnerability_type": vulnerability.vulnerability_type,
            "description": vulnerability.description,
            "severity": vulnerability.severity.value,
            "status": vulnerability.status.value,
            "confidence": vulnerability.confidence.value,
            "priority": vulnerability.priority.value,
            "evidence": vulnerability.evidence,
            "exploitation_steps": vulnerability.exploitation_steps,
            "impact": vulnerability.impact,
            "remediation": vulnerability.remediation,
            "mitigation_recommendations": vulnerability.mitigation_recommendations,
            "cve": vulnerability.cve,
            "cvss_score": vulnerability.cvss_score,
            "created_at": vulnerability.created_at,
            "updated_at": vulnerability.updated_at,
            "sources": vulnerability.sources,
            "report_id": vulnerability.report_id
        }
        
        if vulnerability.id:
            doc["_id"] = vulnerability.id
        
        return doc
    
    def _from_document(self, doc: Dict[str, Any]) -> Vulnerability:
        """Convierte un documento MongoDB a vulnerabilidad"""
        return Vulnerability(
            id=doc["_id"],
            name=doc["name"],
            vulnerability_type=doc["vulnerability_type"],
            description=doc["description"],
            severity=SeverityLevel(doc["severity"]),
            status=VulnerabilityStatus(doc["status"]),
            confidence=ConfidenceLevel(doc["confidence"]),
            priority=Priority(doc["priority"]),
            evidence=doc.get("evidence", []),
            exploitation_steps=doc.get("exploitation_steps", []),
            impact=doc.get("impact", ""),
            remediation=doc.get("remediation", ""),
            mitigation_recommendations=doc.get("mitigation_recommendations", []),
            cve=doc.get("cve"),
            cvss_score=doc.get("cvss_score"),
            created_at=doc.get("created_at", datetime.utcnow()),
            updated_at=doc.get("updated_at", datetime.utcnow()),
            sources=doc.get("sources", []),
            report_id=doc.get("report_id")
        )


class MongoDBReportRepository(ReportRepository):
    """Implementación MongoDB del repositorio de reportes"""
    
    def __init__(self, database: Database):
        self.collection: Collection = database.reports
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        """Crea índices necesarios"""
        try:
            self.collection.create_index("file_path", unique=True)
            self.collection.create_index("created_at")
            self.collection.create_index([("title", "text"), ("client", "text")])
        except Exception as e:
            logger.warning(f"Error creating report indexes: {e}")
    
    async def save(self, report: Report) -> str:
        """Guarda un reporte"""
        doc = self._to_document(report)
        
        if report.id:
            result = self.collection.replace_one(
                {"_id": report.id},
                doc,
                upsert=True
            )
            return report.id
        else:
            result = self.collection.insert_one(doc)
            return str(result.inserted_id)
    
    async def find_by_id(self, report_id: str) -> Optional[Report]:
        """Busca un reporte por ID"""
        try:
            doc = self.collection.find_one({"_id": report_id})
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding report by ID {report_id}: {e}")
            return None
    
    async def find_by_file_path(self, file_path: str) -> Optional[Report]:
        """Busca un reporte por ruta de archivo"""
        try:
            doc = self.collection.find_one({"file_path": file_path})
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding report by file path {file_path}: {e}")
            return None
    
    async def find_all(self) -> List[Report]:
        """Obtiene todos los reportes"""
        try:
            docs = self.collection.find().sort("created_at", -1)
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding all reports: {e}")
            return []
    
    async def update(self, report: Report) -> bool:
        """Actualiza un reporte"""
        if not report.id:
            return False
        
        try:
            doc = self._to_document(report)
            result = self.collection.replace_one(
                {"_id": report.id},
                doc
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating report {report.id}: {e}")
            return False
    
    async def delete(self, report_id: str) -> bool:
        """Elimina un reporte"""
        try:
            result = self.collection.delete_one({"_id": report_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting report {report_id}: {e}")
            return False
    
    def _to_document(self, report: Report) -> Dict[str, Any]:
        """Convierte un reporte a documento MongoDB"""
        doc = {
            "title": report.title,
            "file_path": report.file_path,
            "client": report.client,
            "consultant": report.consultant,
            "version": report.version,
            "targets": report.targets,
            "applications": report.applications,
            "limitations": report.limitations,
            "test_accounts": report.test_accounts,
            "access_levels": report.access_levels,
            "tools_used": report.tools_used,
            "techniques": report.techniques,
            "standards": report.standards,
            "key_findings": report.key_findings,
            "general_recommendations": report.general_recommendations,
            "created_at": report.created_at,
            "report_date": report.report_date,
            "processed_at": report.processed_at
        }
        
        if report.id:
            doc["_id"] = report.id
        
        return doc
    
    def _from_document(self, doc: Dict[str, Any]) -> Report:
        """Convierte un documento MongoDB a reporte"""
        return Report(
            id=doc["_id"],
            title=doc["title"],
            file_path=doc["file_path"],
            client=doc.get("client", ""),
            consultant=doc.get("consultant", ""),
            version=doc.get("version", ""),
            targets=doc.get("targets", []),
            applications=doc.get("applications", []),
            limitations=doc.get("limitations", ""),
            test_accounts=doc.get("test_accounts", {}),
            access_levels=doc.get("access_levels", []),
            tools_used=doc.get("tools_used", []),
            techniques=doc.get("techniques", []),
            standards=doc.get("standards", []),
            key_findings=doc.get("key_findings", []),
            general_recommendations=doc.get("general_recommendations", []),
            created_at=doc.get("created_at", datetime.utcnow()),
            report_date=doc.get("report_date"),
            processed_at=doc.get("processed_at")
        )


class MongoDBAnalysisRepository(AnalysisRepository):
    """Implementación MongoDB del repositorio de análisis"""
    
    def __init__(self, database: Database):
        self.collection: Collection = database.analyses
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        """Crea índices necesarios"""
        try:
            self.collection.create_index("report_id")
            self.collection.create_index("analysis_type")
            self.collection.create_index("agent_name")
            self.collection.create_index("created_at")
        except Exception as e:
            logger.warning(f"Error creating analysis indexes: {e}")
    
    async def save(self, analysis: Analysis) -> str:
        """Guarda un análisis"""
        doc = self._to_document(analysis)
        
        if analysis.id:
            result = self.collection.replace_one(
                {"_id": analysis.id},
                doc,
                upsert=True
            )
            return analysis.id
        else:
            result = self.collection.insert_one(doc)
            return str(result.inserted_id)
    
    async def find_by_id(self, analysis_id: str) -> Optional[Analysis]:
        """Busca un análisis por ID"""
        try:
            doc = self.collection.find_one({"_id": analysis_id})
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding analysis by ID {analysis_id}: {e}")
            return None
    
    async def find_by_report_id(self, report_id: str) -> List[Analysis]:
        """Busca análisis por ID de reporte"""
        try:
            docs = self.collection.find({"report_id": report_id}).sort("created_at", 1)
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding analyses by report ID {report_id}: {e}")
            return []
    
    async def find_by_type(self, analysis_type: AnalysisType) -> List[Analysis]:
        """Busca análisis por tipo"""
        try:
            docs = self.collection.find({"analysis_type": analysis_type.value})
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding analyses by type {analysis_type}: {e}")
            return []
    
    async def update(self, analysis: Analysis) -> bool:
        """Actualiza un análisis"""
        if not analysis.id:
            return False
        
        try:
            doc = self._to_document(analysis)
            result = self.collection.replace_one(
                {"_id": analysis.id},
                doc
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating analysis {analysis.id}: {e}")
            return False
    
    async def delete(self, analysis_id: str) -> bool:
        """Elimina un análisis"""
        try:
            result = self.collection.delete_one({"_id": analysis_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting analysis {analysis_id}: {e}")
            return False

    async def find_all(self, limit: int = 100, offset: int = 0) -> List[Analysis]:
        """Obtiene todos los análisis con paginación"""
        try:
            docs = list(self.collection.find().skip(offset).limit(limit))
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding all analyses: {e}")
            return []

    def _to_document(self, analysis: Analysis) -> Dict[str, Any]:
        """Convierte un análisis a documento MongoDB"""
        doc = {
            "analysis_type": analysis.analysis_type.value,
            "agent_name": analysis.agent_name,
            "report_id": analysis.report_id,
            "vulnerability_ids": analysis.vulnerability_ids,
            "source_directory": analysis.source_directory,
            "target_host": analysis.target_host,
            "model_used": analysis.model_used,
            "status": analysis.status,
            "vulnerabilities_found": analysis.vulnerabilities_found,
            "vulnerabilities_validated": analysis.vulnerabilities_validated,
            "total_requests_made": analysis.total_requests_made,
            "created_at": analysis.created_at,
            "started_at": analysis.started_at,
            "completed_at": analysis.completed_at,
            "execution_time_seconds": analysis.execution_time_seconds,
            "context": analysis.context,
            "error_message": analysis.error_message
        }
        
        if analysis.id:
            doc["_id"] = analysis.id
        
        return doc
    
    def _from_document(self, doc: Dict[str, Any]) -> Analysis:
        """Convierte un documento MongoDB a análisis"""
        return Analysis(
            id=doc["_id"],
            analysis_type=AnalysisType(doc["analysis_type"]),
            agent_name=doc["agent_name"],
            report_id=doc["report_id"],
            vulnerability_ids=doc.get("vulnerability_ids", []),
            source_directory=doc.get("source_directory"),
            target_host=doc.get("target_host"),
            model_used=doc.get("model_used", "gpt-5-nano"),
            status=doc.get("status", "pending"),
            vulnerabilities_found=doc.get("vulnerabilities_found", 0),
            vulnerabilities_validated=doc.get("vulnerabilities_validated", 0),
            total_requests_made=doc.get("total_requests_made", 0),
            created_at=doc.get("created_at", datetime.utcnow()),
            started_at=doc.get("started_at"),
            completed_at=doc.get("completed_at"),
            execution_time_seconds=doc.get("execution_time_seconds"),
            context=doc.get("context", {}),
            error_message=doc.get("error_message")
        )


class MongoDBTriageResultRepository(TriageResultRepository):
    """Implementación MongoDB del repositorio de resultados de triage"""
    
    def __init__(self, database: Database):
        self.collection: Collection = database.triage_results
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        """Crea índices necesarios"""
        try:
            self.collection.create_index("report_id", unique=True)
            self.collection.create_index("created_at")
        except Exception as e:
            logger.warning(f"Error creating triage result indexes: {e}")
    
    async def save(self, triage_result: TriageResult) -> str:
        """Guarda un resultado de triage"""
        doc = self._to_document(triage_result)
        
        if triage_result.id:
            result = self.collection.replace_one(
                {"_id": triage_result.id},
                doc,
                upsert=True
            )
            return triage_result.id
        else:
            result = self.collection.insert_one(doc)
            return str(result.inserted_id)
    
    async def find_by_id(self, triage_id: str) -> Optional[TriageResult]:
        """Busca un resultado de triage por ID"""
        try:
            doc = self.collection.find_one({"_id": triage_id})
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding triage result by ID {triage_id}: {e}")
            return None
    
    async def find_by_report_id(self, report_id: str) -> Optional[TriageResult]:
        """Busca un resultado de triage por ID de reporte"""
        try:
            doc = self.collection.find_one({"report_id": report_id})
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding triage result by report ID {report_id}: {e}")
            return None
    
    async def find_all(self) -> List[TriageResult]:
        """Obtiene todos los resultados de triage"""
        try:
            docs = self.collection.find().sort("created_at", -1)
            return [self._from_document(doc) for doc in docs]
        except Exception as e:
            logger.error(f"Error finding all triage results: {e}")
            return []
    
    async def update(self, triage_result: TriageResult) -> bool:
        """Actualiza un resultado de triage"""
        if not triage_result.id:
            return False
        
        try:
            doc = self._to_document(triage_result)
            result = self.collection.replace_one(
                {"_id": triage_result.id},
                doc
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating triage result {triage_result.id}: {e}")
            return False
    
    async def delete(self, triage_id: str) -> bool:
        """Elimina un resultado de triage"""
        try:
            result = self.collection.delete_one({"_id": triage_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting triage result {triage_id}: {e}")
            return False

    async def find_latest_by_report_id(self, report_id: str) -> Optional[TriageResult]:
        """Busca el resultado de triage más reciente por ID de reporte"""
        try:
            doc = self.collection.find_one(
                {"report_id": report_id},
                sort=[("created_at", -1)]
            )
            return self._from_document(doc) if doc else None
        except Exception as e:
            logger.error(f"Error finding latest triage result by report ID {report_id}: {e}")
            return None

    def _to_document(self, triage_result: TriageResult) -> Dict[str, Any]:
        """Convierte un resultado de triage a documento MongoDB"""
        doc = {
            "report_id": triage_result.report_id,
            "analysis_ids": triage_result.analysis_ids,
            "triage_summary": triage_result.triage_summary,
            "severity_distribution": {k.value: v for k, v in triage_result.severity_distribution.items()},
            "consolidated_vulnerability_ids": triage_result.consolidated_vulnerability_ids,
            "created_at": triage_result.created_at,
            "analysis_completed_at": triage_result.analysis_completed_at
        }
        
        if triage_result.id:
            doc["_id"] = triage_result.id
        
        return doc
    
    def _from_document(self, doc: Dict[str, Any]) -> TriageResult:
        """Convierte un documento MongoDB a resultado de triage"""
        severity_distribution = {}
        for k, v in doc.get("severity_distribution", {}).items():
            try:
                severity_distribution[SeverityLevel(k)] = v
            except ValueError:
                continue
        
        return TriageResult(
            id=doc["_id"],
            report_id=doc["report_id"],
            analysis_ids=doc.get("analysis_ids", []),
            triage_summary=doc.get("triage_summary", {}),
            severity_distribution=severity_distribution,
            consolidated_vulnerability_ids=doc.get("consolidated_vulnerability_ids", []),
            created_at=doc.get("created_at", datetime.utcnow()),
            analysis_completed_at=doc.get("analysis_completed_at")
        )
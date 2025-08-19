"""
Servicio de Triage Final

Este servicio encapsula la lógica de triage final y priorización
utilizando el TriageAgent.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
from collections import Counter

from ...domain.entities import (
    Vulnerability, Analysis, TriageResult, SeverityLevel,
    VulnerabilityStatus, ConfidenceLevel
)
from ...domain.repositories import (
    VulnerabilityRepository, AnalysisRepository, TriageResultRepository
)
from ...infrastructure.agents.triage import TriageAgent

logger = logging.getLogger(__name__)


class TriageService:
    """Servicio para realizar triage final y priorización de vulnerabilidades"""
    
    def __init__(
        self,
        triage_result_repository: TriageResultRepository,
        vulnerability_repository: VulnerabilityRepository,
        analysis_repository: AnalysisRepository
    ):
        self.triage_result_repository = triage_result_repository
        self.vulnerability_repository = vulnerability_repository
        self.analysis_repository = analysis_repository
        self.triage_agent = TriageAgent(
            vulnerability_repository, analysis_repository, triage_result_repository
        )
    
    async def perform_triage(
        self, 
        report_id: str,
        vulnerabilities: List[Vulnerability], 
        analyses: List[Analysis]
    ) -> TriageResult:
        """
        Realiza el triage final de vulnerabilidades y análisis
        
        Args:
            report_id: ID del reporte asociado
            vulnerabilities: Lista de vulnerabilidades a procesar
            analyses: Lista de análisis realizados
            
        Returns:
            Resultado del triage
        """
        logger.info(f"Starting triage for report {report_id}")
        logger.info(f"Processing {len(vulnerabilities)} vulnerabilities and {len(analyses)} analyses")
        
        try:
            # Usar el agente de triage para realizar el análisis inteligente
            triage_result = await self.triage_agent.perform_triage(
                report_id, vulnerabilities, analyses
            )
            
            logger.info(f"Triage completed for report {report_id}")
            
            return triage_result
            
        except Exception as e:
            logger.error(f"Error during triage: {e}")
            raise
    
    async def _basic_triage(
        self, 
        report_id: str, 
        vulnerabilities: List[Vulnerability], 
        analyses: List[Analysis]
    ) -> TriageResult:
        """Implementación básica de triage"""
        
        # Deduplicar vulnerabilidades por tipo y ubicación
        unique_vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        
        # Calcular distribución de severidad
        severity_distribution = self._calculate_severity_distribution(unique_vulnerabilities)
        
        # Generar resumen de triage
        triage_summary = {
            "total_vulnerabilities_before_deduplication": len(vulnerabilities),
            "unique_vulnerabilities_after_deduplication": len(unique_vulnerabilities),
            "sources_processed": ["pdf_report", "static_analysis"],
            "source_files_analyzed": len(set(a.file_path for a in analyses if a.file_path)),
            "analysis_completed_at": datetime.utcnow().isoformat()
        }
        
        # Crear resultado de triage
        triage_result = TriageResult(
            report_id=report_id,
            consolidated_vulnerability_ids=[v.id for v in unique_vulnerabilities],
            vulnerabilities_by_severity={sev.value: count for sev, count in severity_distribution.items()},
            total_vulnerabilities_before_deduplication=len(vulnerabilities),
            total_unique_vulnerabilities=len(unique_vulnerabilities),
            sources_processed=len(set(a.analysis_type for a in analyses)),
            source_files=[f"pdf_report", "static_analysis"],
            triage_summary=triage_summary,
            analysis_completed_at=datetime.utcnow()
        )
        
        return triage_result
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplica vulnerabilidades basándose en tipo y ubicación"""
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # Crear una clave única basada en tipo, archivo y línea
            key = (
                vuln.vulnerability_type,
                vuln.file_path or "",
                vuln.line_number or 0
            )
            
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        return unique_vulnerabilities
    
    def _calculate_severity_distribution(self, vulnerabilities: List[Vulnerability]) -> Dict[SeverityLevel, int]:
        """Calcula la distribución de severidad de las vulnerabilidades"""
        severity_counts = Counter(vuln.severity for vuln in vulnerabilities)
        
        # Asegurar que todas las severidades estén representadas
        distribution = {}
        for severity in SeverityLevel:
            distribution[severity] = severity_counts.get(severity, 0)
        
        return distribution
    
    async def get_triage_result_by_report_id(self, report_id: str) -> TriageResult:
        """Obtiene el resultado de triage por ID de reporte"""
        return await self.triage_result_repository.find_by_report_id(report_id)
    
    async def get_triage_result_by_id(self, triage_id: str) -> TriageResult:
        """Obtiene un resultado de triage por su ID"""
        return await self.triage_result_repository.find_by_id(triage_id)
    
    async def list_triage_results(self, limit: int = 50, offset: int = 0) -> List[TriageResult]:
        """Lista todos los resultados de triage"""
        return await self.triage_result_repository.find_all(limit=limit, offset=offset)
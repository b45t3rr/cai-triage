"""
Servicio de Análisis Estático

Este servicio encapsula la lógica de análisis estático de código
utilizando el StaticAnalysisAgent.
"""

import logging
from typing import List
from datetime import datetime

from ...domain.entities import Vulnerability, Analysis, VulnerabilityStatus
from ...domain.repositories import VulnerabilityRepository, AnalysisRepository
from ...infrastructure.agents.static_agent import StaticAnalysisAgent

logger = logging.getLogger(__name__)


class StaticAnalysisService:
    """Servicio para realizar análisis estático de vulnerabilidades"""
    
    def __init__(
        self,
        analysis_repository: AnalysisRepository,
        vulnerability_repository: VulnerabilityRepository
    ):
        self.analysis_repository = analysis_repository
        self.vulnerability_repository = vulnerability_repository
        self.static_analysis_agent = StaticAnalysisAgent(
            vulnerability_repository, analysis_repository
        )
    
    async def analyze_vulnerabilities(
        self, 
        vulnerabilities: List[Vulnerability], 
        source_path: str
    ) -> List[Analysis]:
        """
        Realiza análisis estático de una lista de vulnerabilidades
        
        Args:
            vulnerabilities: Lista de vulnerabilidades a analizar
            source_path: Ruta al código fuente para análisis
            
        Returns:
            Lista de análisis generados
        """
        logger.info(f"Starting static analysis for {len(vulnerabilities)} vulnerabilities")
        logger.info(f"Source path: {source_path}")
        
        try:
            # Filtrar solo vulnerabilidades que necesitan análisis estático
            pending_vulnerabilities = [
                vuln for vuln in vulnerabilities 
                if vuln.status == VulnerabilityStatus.VULNERABLE
            ]
            
            if not pending_vulnerabilities:
                logger.info("No vulnerabilities pending static analysis")
                return []
            
            logger.info(f"Analyzing {len(pending_vulnerabilities)} pending vulnerabilities")
            
            # Ejecutar análisis estático usando el agente
            analyses = await self.static_analysis_agent.validate_vulnerabilities(
                pending_vulnerabilities, source_path
            )
            
            logger.info(f"Static analysis completed. Generated {len(analyses)} analyses")
            
            return analyses
            
        except Exception as e:
            logger.error(f"Error during static analysis: {e}")
            raise
    
    async def get_analysis_by_vulnerability_id(self, vulnerability_id: str) -> List[Analysis]:
        """Obtiene todos los análisis de una vulnerabilidad específica"""
        return await self.analysis_repository.find_by_vulnerability_id(vulnerability_id)
    
    async def get_analysis_by_id(self, analysis_id: str) -> Analysis:
        """Obtiene un análisis por su ID"""
        return await self.analysis_repository.find_by_id(analysis_id)
    
    async def list_static_analyses(self, limit: int = 50, offset: int = 0) -> List[Analysis]:
        """Lista todos los análisis estáticos realizados"""
        from ...domain.entities import AnalysisType
        return await self.analysis_repository.find_by_type(
            AnalysisType.STATIC_ANALYSIS, limit=limit, offset=offset
        )
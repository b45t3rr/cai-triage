"""
Servicio de Análisis Dinámico

Este servicio encapsula la lógica de análisis dinámico y explotación
utilizando el DynamicExploitationAgent.
"""

import logging
from typing import List
from datetime import datetime

from ...domain.entities import Vulnerability, Analysis, AnalysisType
from ...domain.repositories import VulnerabilityRepository, AnalysisRepository
from ...infrastructure.agents.dynamic_agent import DynamicExploitationAgent

logger = logging.getLogger(__name__)


class DynamicAnalysisService:
    """Servicio para realizar análisis dinámico de vulnerabilidades"""
    
    def __init__(
        self,
        analysis_repository: AnalysisRepository,
        vulnerability_repository: VulnerabilityRepository
    ):
        self.analysis_repository = analysis_repository
        self.vulnerability_repository = vulnerability_repository
        self.dynamic_analysis_agent = DynamicExploitationAgent(
            vulnerability_repository, analysis_repository
        )
    
    async def analyze_vulnerabilities(
        self, 
        vulnerabilities: List[Vulnerability], 
        target_url: str
    ) -> List[Analysis]:
        """
        Analiza vulnerabilidades usando análisis dinámico
        
        Args:
            vulnerabilities: Lista de vulnerabilidades a analizar
            target_url: URL objetivo para el análisis dinámico
            
        Returns:
            Lista de análisis dinámicos realizados
        """
        logger.info(f"Starting dynamic analysis for {len(vulnerabilities)} vulnerabilities")
        logger.info(f"Target URL: {target_url}")
        
        try:
            # Usar el agente dinámico para realizar el análisis
            analyses = await self.dynamic_analysis_agent.exploit_vulnerabilities(
                vulnerabilities, target_url
            )
            
            logger.info(f"Dynamic analysis completed: {len(analyses)} analyses created")
            return analyses
            
        except Exception as e:
            logger.error(f"Error during dynamic analysis: {e}")
            raise
    
    async def get_analysis_by_vulnerability_id(self, vulnerability_id: str) -> List[Analysis]:
        """Obtiene todos los análisis dinámicos de una vulnerabilidad específica"""
        from ...domain.entities import AnalysisType
        analyses = await self.analysis_repository.find_by_vulnerability_id(vulnerability_id)
        return [a for a in analyses if a.analysis_type == AnalysisType.DYNAMIC_ANALYSIS]
    
    async def get_analysis_by_id(self, analysis_id: str) -> Analysis:
        """Obtiene un análisis por su ID"""
        return await self.analysis_repository.find_by_id(analysis_id)
    
    async def list_dynamic_analyses(self, limit: int = 50, offset: int = 0) -> List[Analysis]:
        """Lista todos los análisis dinámicos realizados"""
        from ...domain.entities import AnalysisType
        return await self.analysis_repository.find_by_type(
            AnalysisType.DYNAMIC_ANALYSIS, limit=limit, offset=offset
        )
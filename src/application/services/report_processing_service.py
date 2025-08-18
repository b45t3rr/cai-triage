"""
Servicio de Procesamiento de Reportes

Este servicio encapsula la lógica de procesamiento de reportes PDF
utilizando el ReportReaderAgent.
"""

import logging
from typing import List, Tuple
from datetime import datetime

from ...domain.entities import Report, Vulnerability
from ...domain.repositories import ReportRepository, VulnerabilityRepository
from ...infrastructure.agents.report_reader import ReportReaderAgent

logger = logging.getLogger(__name__)


class ReportProcessingService:
    """Servicio para procesar reportes PDF y extraer vulnerabilidades"""
    
    def __init__(
        self,
        report_repository: ReportRepository,
        vulnerability_repository: VulnerabilityRepository
    ):
        self.report_repository = report_repository
        self.vulnerability_repository = vulnerability_repository
        self.report_reader_agent = ReportReaderAgent(
            report_repository, vulnerability_repository
        )
    
    async def process_pdf_report(self, pdf_path: str) -> Tuple[Report, List[Vulnerability]]:
        """
        Procesa un reporte PDF y extrae las vulnerabilidades
        
        Args:
            pdf_path: Ruta al archivo PDF del reporte
            
        Returns:
            Tupla con el reporte procesado y lista de vulnerabilidades extraídas
        """
        logger.info(f"Processing PDF report: {pdf_path}")
        
        try:
            # Procesar el PDF usando el agente
            report = await self.report_reader_agent.process_pdf_report(pdf_path)
            
            # Obtener las vulnerabilidades asociadas al reporte
            vulnerabilities = await self.vulnerability_repository.find_by_report_id(report.id)
            
            logger.info(f"Successfully processed report {report.id} with {len(vulnerabilities)} vulnerabilities")
            
            return report, vulnerabilities
            
        except Exception as e:
            logger.error(f"Error processing PDF report {pdf_path}: {e}")
            raise
    
    async def get_report_by_id(self, report_id: str) -> Report:
        """Obtiene un reporte por su ID"""
        return await self.report_repository.find_by_id(report_id)
    
    async def get_vulnerabilities_by_report_id(self, report_id: str) -> List[Vulnerability]:
        """Obtiene todas las vulnerabilidades de un reporte"""
        return await self.vulnerability_repository.find_by_report_id(report_id)
    
    async def list_reports(self, limit: int = 50, offset: int = 0) -> List[Report]:
        """Lista todos los reportes procesados"""
        return await self.report_repository.find_all(limit=limit, offset=offset)
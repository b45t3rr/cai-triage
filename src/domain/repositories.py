#!/usr/bin/env python3
"""
Interfaces de repositorio para el dominio

Este módulo define las interfaces abstractas que deben implementar
los repositorios en la capa de infraestructura.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from .entities import Vulnerability, Report, Analysis, TriageResult


class VulnerabilityRepository(ABC):
    """Interface para el repositorio de vulnerabilidades"""
    
    @abstractmethod
    async def save(self, vulnerability: Vulnerability) -> str:
        """Guarda una vulnerabilidad y retorna su ID"""
        pass
    
    @abstractmethod
    async def find_by_id(self, vulnerability_id: str) -> Optional[Vulnerability]:
        """Busca una vulnerabilidad por ID"""
        pass
    
    @abstractmethod
    async def find_by_report_id(self, report_id: str) -> List[Vulnerability]:
        """Busca todas las vulnerabilidades de un reporte"""
        pass
    
    @abstractmethod
    async def find_by_name_and_type(self, name: str, vulnerability_type: str) -> List[Vulnerability]:
        """Busca vulnerabilidades por nombre y tipo (para deduplicación)"""
        pass
    
    @abstractmethod
    async def update(self, vulnerability: Vulnerability) -> bool:
        """Actualiza una vulnerabilidad existente"""
        pass
    
    @abstractmethod
    async def delete(self, vulnerability_id: str) -> bool:
        """Elimina una vulnerabilidad"""
        pass
    
    @abstractmethod
    async def find_all(self, limit: int = 100, offset: int = 0) -> List[Vulnerability]:
        """Obtiene todas las vulnerabilidades con paginación"""
        pass
    
    @abstractmethod
    async def count_by_severity(self, report_id: Optional[str] = None) -> Dict[str, int]:
        """Cuenta vulnerabilidades por severidad"""
        pass


class ReportRepository(ABC):
    """Interface para el repositorio de reportes"""
    
    @abstractmethod
    async def save(self, report: Report) -> str:
        """Guarda un reporte y retorna su ID"""
        pass
    
    @abstractmethod
    async def find_by_id(self, report_id: str) -> Optional[Report]:
        """Busca un reporte por ID"""
        pass
    
    @abstractmethod
    async def find_by_file_path(self, file_path: str) -> Optional[Report]:
        """Busca un reporte por ruta de archivo"""
        pass
    
    @abstractmethod
    async def update(self, report: Report) -> bool:
        """Actualiza un reporte existente"""
        pass
    
    @abstractmethod
    async def delete(self, report_id: str) -> bool:
        """Elimina un reporte"""
        pass
    
    @abstractmethod
    async def find_all(self, limit: int = 100, offset: int = 0) -> List[Report]:
        """Obtiene todos los reportes con paginación"""
        pass


class AnalysisRepository(ABC):
    """Interface para el repositorio de análisis"""
    
    @abstractmethod
    async def save(self, analysis: Analysis) -> str:
        """Guarda un análisis y retorna su ID"""
        pass
    
    @abstractmethod
    async def find_by_id(self, analysis_id: str) -> Optional[Analysis]:
        """Busca un análisis por ID"""
        pass
    
    @abstractmethod
    async def find_by_report_id(self, report_id: str) -> List[Analysis]:
        """Busca todos los análisis de un reporte"""
        pass
    
    @abstractmethod
    async def find_by_type(self, analysis_type: str, report_id: Optional[str] = None) -> List[Analysis]:
        """Busca análisis por tipo"""
        pass
    
    @abstractmethod
    async def update(self, analysis: Analysis) -> bool:
        """Actualiza un análisis existente"""
        pass
    
    @abstractmethod
    async def delete(self, analysis_id: str) -> bool:
        """Elimina un análisis"""
        pass
    
    @abstractmethod
    async def find_all(self, limit: int = 100, offset: int = 0) -> List[Analysis]:
        """Obtiene todos los análisis con paginación"""
        pass


class TriageResultRepository(ABC):
    """Interface para el repositorio de resultados de triage"""
    
    @abstractmethod
    async def save(self, triage_result: TriageResult) -> str:
        """Guarda un resultado de triage y retorna su ID"""
        pass
    
    @abstractmethod
    async def find_by_id(self, triage_id: str) -> Optional[TriageResult]:
        """Busca un resultado de triage por ID"""
        pass
    
    @abstractmethod
    async def find_by_report_id(self, report_id: str) -> List[TriageResult]:
        """Busca todos los resultados de triage de un reporte"""
        pass
    
    @abstractmethod
    async def update(self, triage_result: TriageResult) -> bool:
        """Actualiza un resultado de triage existente"""
        pass
    
    @abstractmethod
    async def delete(self, triage_id: str) -> bool:
        """Elimina un resultado de triage"""
        pass
    
    @abstractmethod
    async def find_latest_by_report_id(self, report_id: str) -> Optional[TriageResult]:
        """Busca el resultado de triage más reciente de un reporte"""
        pass
"""
Infrastructure layer - Agents

Este módulo contiene las implementaciones de los agentes de IA que realizan
el análisis de vulnerabilidades. Los agentes están adaptados para trabajar
con la arquitectura Clean Architecture y MongoDB.
"""

from .report_reader import ReportReaderAgent
from .static_agent import StaticAnalysisAgent  
from .dynamic_agent import DynamicExploitationAgent
from .triage import TriageAgent

__all__ = [
    'ReportReaderAgent',
    'StaticAnalysisAgent', 
    'DynamicExploitationAgent',
    'TriageAgent'
]
#!/usr/bin/env python3
"""
Servicios de aplicación

Este módulo contiene los servicios que orquestan el flujo completo de análisis
de vulnerabilidades usando los diferentes agentes.
"""

import logging
import os
import tempfile
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from ..domain.entities import (
    Report, Vulnerability, Analysis, TriageResult,
    AnalysisType, VulnerabilityStatus, SeverityLevel
)
from ..domain.repositories import (
    ReportRepository, VulnerabilityRepository, 
    AnalysisRepository, TriageResultRepository
)
from ..domain.services import (
    VulnerabilityDeduplicationService,
    VulnerabilityPriorityService,
    VulnerabilityMitigationService
)

logger = logging.getLogger(__name__)


class ReportProcessingService:
    """Servicio para procesar reportes de vulnerabilidades"""
    
    def __init__(
        self,
        report_repo: ReportRepository,
        vulnerability_repo: VulnerabilityRepository
    ):
        self.report_repo = report_repo
        self.vulnerability_repo = vulnerability_repo
    
    async def process_report(self, pdf_path: str, model: str = "openai:gpt-5-nano") -> Report:
        """Procesa un reporte PDF y extrae vulnerabilidades"""
        logger.info(f"Processing report: {pdf_path}")
        
        # Verificar si el reporte ya fue procesado
        existing_report = await self.report_repo.find_by_file_path(pdf_path)
        if existing_report:
            logger.info(f"Report already processed: {existing_report.id}")
            return existing_report
        
        # Importar y ejecutar el report_reader
        from ..infrastructure.agents.report_reader import ReportReaderAgent
        
        try:
            # Crear instancia del report reader
            reader = ReportReaderAgent(self.report_repo, self.vulnerability_repo)
            
            # Procesar el PDF
            report = await reader.process_pdf_report(pdf_path)
            
            if not report:
                raise ValueError("Failed to process PDF report")
            
            logger.info(f"Successfully processed report {report.id}")
            return report
            
        except Exception as e:
            logger.error(f"Error processing report {pdf_path}: {e}")
            raise
    
    def _create_vulnerability_from_data(self, vuln_data: Dict[str, Any], report_id: str) -> Vulnerability:
        """Crea una entidad Vulnerability a partir de los datos extraídos"""
        # Mapear severidad
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "informational": SeverityLevel.INFO
        }
        
        severity_str = vuln_data.get("severity", "medium").lower()
        severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)
        
        vulnerability = Vulnerability(
            name=vuln_data.get("name", "Unknown Vulnerability"),
            vulnerability_type=vuln_data.get("type", "Unknown"),
            description=vuln_data.get("description", ""),
            severity=severity,
            status=VulnerabilityStatus.UNKNOWN,
            impact=vuln_data.get("impact", ""),
            remediation=vuln_data.get("remediation", ""),
            exploitation_steps=vuln_data.get("exploitation_steps", []),
            cve=vuln_data.get("cve"),
            cvss_score=vuln_data.get("cvss_score"),
            sources=["report_reader"],
            report_id=report_id
        )
        
        # Generar recomendaciones de mitigación
        mitigation_recommendations = VulnerabilityMitigationService.generate_mitigation_recommendations(vulnerability)
        vulnerability.mitigation_recommendations = mitigation_recommendations
        
        # Calcular prioridad
        vulnerability.priority = VulnerabilityPriorityService.calculate_priority(vulnerability)
        
        return vulnerability


class StaticAnalysisService:
    """Servicio para análisis estático de vulnerabilidades"""
    
    def __init__(
        self,
        analysis_repo: AnalysisRepository,
        vulnerability_repo: VulnerabilityRepository
    ):
        self.analysis_repo = analysis_repo
        self.vulnerability_repo = vulnerability_repo
    
    def analyze_vulnerabilities(
        self, 
        report_id: str, 
        source_path: str, 
        model: str = "openai:gpt-5-nano"
    ) -> Analysis:
        """Ejecuta análisis estático de vulnerabilidades"""
        logger.info(f"Starting static analysis for report {report_id}")
        
        # Crear análisis
        analysis = Analysis(
            analysis_type=AnalysisType.STATIC,
            agent_name="static_agent",
            report_id=report_id,
            configuration={
                "source_directory": source_path,
                "model": model,
                "tools": ["semgrep"]
            }
        )
        
        analysis_id = self.analysis_repo.save(analysis)
        analysis.id = analysis_id
        analysis.start()
        
        try:
            # Obtener vulnerabilidades del reporte
            vulnerabilities = self.vulnerability_repo.find_by_report_id(report_id)
            analysis.vulnerability_ids = [v.id for v in vulnerabilities if v.id]
            
            # Crear archivo temporal con vulnerabilidades para el agente
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                import json
                
                # Preparar datos para el agente estático
                vuln_data = []
                for vuln in vulnerabilities:
                    vuln_data.append({
                        "id": vuln.id,
                        "name": vuln.name,
                        "type": vuln.vulnerability_type,
                        "description": vuln.description,
                        "severity": vuln.severity.value,
                        "exploitation_steps": vuln.exploitation_steps,
                        "evidence": vuln.evidence
                    })
                
                json.dump({"vulnerabilities": vuln_data}, temp_file, indent=2)
                temp_report_path = temp_file.name
            
            # Importar y ejecutar el static_agent
            from static_agent import StaticAnalysisAgent
            
            static_agent = StaticAnalysisAgent()
            results = static_agent.validate_vulnerabilities(
                source_directory=source_path,
                report_json_path=temp_report_path
            )
            
            # Limpiar archivo temporal
            os.unlink(temp_report_path)
            
            # Procesar resultados
            validated_count = 0
            for result in results:
                vuln_id = result.get("vulnerability_id")
                if vuln_id:
                    vulnerability = self.vulnerability_repo.find_by_id(vuln_id)
                    if vulnerability:
                        # Actualizar estado de vulnerabilidad
                        if result.get("status") == "vulnerable":
                            vulnerability.status = VulnerabilityStatus.VULNERABLE
                            validated_count += 1
                        else:
                            vulnerability.status = VulnerabilityStatus.NOT_VULNERABLE
                        
                        # Agregar evidencia del análisis estático
                        evidence = result.get("evidence", [])
                        for ev in evidence:
                            vulnerability.add_evidence(ev, "static_analysis")
                        
                        # Actualizar confianza
                        confidence_map = {
                            "HIGH": "HIGH",
                            "MEDIUM": "MEDIUM", 
                            "LOW": "LOW"
                        }
                        if result.get("confidence") in confidence_map:
                            from ..domain.entities import ConfidenceLevel
                            vulnerability.confidence = ConfidenceLevel(confidence_map[result.get("confidence")])
                        
                        # Agregar fuente
                        if "static_analysis" not in vulnerability.sources:
                            vulnerability.sources.append("static_analysis")
                        
                        self.vulnerability_repo.update(vulnerability)
            
            # Completar análisis
            analysis.complete({
                "status": "completed",
                "vulnerabilities_analyzed": len(vulnerabilities),
                "vulnerabilities_validated": validated_count,
                "tool_results": results
            })
            
            self.analysis_repo.update(analysis)
            
            logger.info(f"Static analysis completed for report {report_id}: {validated_count}/{len(vulnerabilities)} validated")
            return analysis
            
        except Exception as e:
            analysis.fail(str(e))
            self.analysis_repo.update(analysis)
            logger.error(f"Static analysis failed for report {report_id}: {e}")
            raise


class DynamicAnalysisService:
    """Servicio para análisis dinámico de vulnerabilidades"""
    
    def __init__(
        self,
        analysis_repo: AnalysisRepository,
        vulnerability_repo: VulnerabilityRepository
    ):
        self.analysis_repo = analysis_repo
        self.vulnerability_repo = vulnerability_repo
    
    async def analyze_vulnerabilities(
        self, 
        report_id: str, 
        target_url: str, 
        model: str = "openai:gpt-5-nano"
    ) -> Analysis:
        """Ejecuta análisis dinámico de vulnerabilidades"""
        logger.info(f"Starting dynamic analysis for report {report_id}")
        
        # Crear análisis
        analysis = Analysis(
            analysis_type=AnalysisType.DYNAMIC,
            agent_name="dynamic_agent",
            report_id=report_id,
            configuration={
                "target_host": target_url,
                "model": model,
                "max_attempts": 10
            }
        )
        
        analysis_id = self.analysis_repo.save(analysis)
        analysis.id = analysis_id
        analysis.start()
        
        try:
            # Obtener vulnerabilidades confirmadas del análisis estático
            vulnerabilities = self.vulnerability_repo.find_by_report_id(report_id)
            confirmed_vulns = [v for v in vulnerabilities if v.status == VulnerabilityStatus.VULNERABLE]
            
            analysis.vulnerability_ids = [v.id for v in confirmed_vulns if v.id]
            
            # Importar y ejecutar el dynamic_agent
            from ..infrastructure.agents.dynamic_agent import DynamicExploitationAgent
            
            dynamic_agent = DynamicExploitationAgent(
                self.vulnerability_repo, self.analysis_repo
            )
            results = await dynamic_agent.exploit_vulnerabilities(
                confirmed_vulns, target_url
            )
            
            # Procesar resultados
            exploited_count = 0
            total_requests = 0
            
            for result in results:
                vuln_id = result.get("vulnerability_id")
                if vuln_id:
                    vulnerability = self.vulnerability_repo.find_by_id(vuln_id)
                    if vulnerability:
                        # Actualizar estado de vulnerabilidad
                        if result.get("status") == "vulnerable":
                            vulnerability.status = VulnerabilityStatus.VULNERABLE
                            exploited_count += 1
                        else:
                            vulnerability.status = VulnerabilityStatus.NOT_VULNERABLE
                        
                        # Agregar evidencia del análisis dinámico
                        evidence = result.get("evidence", [])
                        for ev in evidence:
                            vulnerability.add_evidence(ev, "dynamic_analysis")
                        
                        # Agregar requests realizados
                        requests_made = result.get("requests_made", 0)
                        total_requests += requests_made
                        
                        # Agregar fuente
                        if "dynamic_analysis" not in vulnerability.sources:
                            vulnerability.sources.append("dynamic_analysis")
                        
                        self.vulnerability_repo.update(vulnerability)
            
            # Completar análisis
            analysis.complete({
                "status": "completed",
                "vulnerabilities_analyzed": len(confirmed_vulns),
                "vulnerabilities_exploited": exploited_count,
                "total_requests_made": total_requests,
                "tool_results": results
            })
            
            self.analysis_repo.update(analysis)
            
            logger.info(f"Dynamic analysis completed for report {report_id}: {exploited_count}/{len(confirmed_vulns)} exploited")
            return analysis
            
        except Exception as e:
            analysis.fail(str(e))
            self.analysis_repo.update(analysis)
            logger.error(f"Dynamic analysis failed for report {report_id}: {e}")
            raise


class TriageService:
    """Servicio para realizar triage de vulnerabilidades"""
    
    def __init__(
        self,
        triage_repo: TriageResultRepository,
        vulnerability_repo: VulnerabilityRepository,
        analysis_repo: AnalysisRepository
    ):
        self.triage_repo = triage_repo
        self.vulnerability_repo = vulnerability_repo
        self.analysis_repo = analysis_repo
    
    def perform_triage(self, report_id: str, model: str = "openai:gpt-5-nano") -> TriageResult:
        """Realiza triage de vulnerabilidades consolidando resultados"""
        logger.info(f"Starting triage for report {report_id}")
        
        try:
            # Obtener análisis del reporte
            analyses = self.analysis_repo.find_by_report_id(report_id)
            
            # Obtener todas las vulnerabilidades
            all_vulnerabilities = self.vulnerability_repo.find_by_report_id(report_id)
            
            # Consolidar vulnerabilidades duplicadas
            consolidated_vulns = VulnerabilityDeduplicationService.consolidate_vulnerabilities(all_vulnerabilities)
            
            # Guardar vulnerabilidades consolidadas
            consolidated_ids = []
            for vuln in consolidated_vulns:
                if vuln.id:
                    self.vulnerability_repo.update(vuln)
                    consolidated_ids.append(vuln.id)
                else:
                    vuln_id = self.vulnerability_repo.save(vuln)
                    consolidated_ids.append(vuln_id)
            
            # Calcular distribución de severidad
            severity_distribution = self.vulnerability_repo.count_by_severity(report_id)
            
            # Crear resumen de triage
            triage_summary = {
                "total_vulnerabilities_before_deduplication": len(all_vulnerabilities),
                "unique_vulnerabilities_after_deduplication": len(consolidated_vulns),
                "sources_processed": list(set(source for vuln in all_vulnerabilities for source in vuln.sources)),
                "source_files_analyzed": len(analyses)
            }
            
            # Crear resultado de triage
            triage_result = TriageResult(
                report_id=report_id,
                analysis_ids=[a.id for a in analyses if a.id],
                triage_summary=triage_summary,
                consolidated_vulnerability_ids=consolidated_ids,
                vulnerabilities_by_severity={sev.value: count for sev, count in severity_distribution.items()},
                total_vulnerabilities_before_deduplication=len(all_vulnerabilities),
                total_unique_vulnerabilities=len(consolidated_vulns),
                sources_processed=len(set(a.analysis_type for a in analyses)),
                source_files=["pdf_report", "static_analysis"],
                analysis_completed_at=datetime.utcnow()
            )
            
            # Guardar resultado
            triage_id = self.triage_repo.save(triage_result)
            triage_result.id = triage_id
            
            logger.info(f"Triage completed for report {report_id}: {len(consolidated_vulns)} unique vulnerabilities")
            return triage_result
            
        except Exception as e:
            logger.error(f"Triage failed for report {report_id}: {e}")
            raise


class VulnerabilityAnalysisOrchestrator:
    """Orquestador principal del flujo completo de análisis"""
    
    def __init__(
        self,
        report_service: ReportProcessingService,
        static_service: StaticAnalysisService,
        dynamic_service: DynamicAnalysisService,
        triage_service: TriageService
    ):
        self.report_service = report_service
        self.static_service = static_service
        self.dynamic_service = dynamic_service
        self.triage_service = triage_service
    
    async def run_complete_analysis(
        self,
        pdf_path: str,
        source_path: str,
        target_url: str,
        model: str = "openai:gpt-5-nano"
    ) -> TriageResult:
        """Ejecuta el flujo completo de análisis"""
        logger.info(f"Starting complete analysis workflow")
        logger.info(f"PDF: {pdf_path}, Source: {source_path}, Target: {target_url}, Model: {model}")
        
        try:
            # 1. Procesar reporte PDF
            logger.info("Step 1: Processing PDF report")
            report = await self.report_service.process_report(pdf_path, model)
            
            # 2. Análisis estático
            logger.info("Step 2: Running static analysis")
            static_analysis = self.static_service.analyze_vulnerabilities(
                report.id, source_path, model
            )
            
            # 3. Análisis dinámico
            logger.info("Step 3: Running dynamic analysis")
            dynamic_analysis = await self.dynamic_service.analyze_vulnerabilities(
                report.id, target_url, model
            )
            
            # 4. Triage
            logger.info("Step 4: Performing triage")
            triage_result = self.triage_service.perform_triage(report.id, model)
            
            logger.info(f"Complete analysis workflow finished successfully")
            logger.info(f"Report ID: {report.id}")
            logger.info(f"Triage ID: {triage_result.id}")
            logger.info(f"Unique vulnerabilities: {len(triage_result.consolidated_vulnerability_ids)}")
            
            return triage_result
            
        except Exception as e:
            logger.error(f"Complete analysis workflow failed: {e}")
            raise
#!/usr/bin/env python3
"""
Report Reader Agent - Extrae texto de PDFs y convierte a entidades de dominio

Este agente se encarga de:
- Extraer texto de archivos PDF
- Interpretar el contenido del reporte de seguridad
- Convertir la información a entidades de dominio (Report, Vulnerability)
- Trabajar con repositorios MongoDB siguiendo Clean Architecture
"""

import os
import sys
import json
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import uuid

try:
    import PyPDF2
except ImportError:
    print("PyPDF2 no está instalado. Instalando...")
    os.system("pip install PyPDF2")
    import PyPDF2

try:
    import pdfplumber
except ImportError:
    print("pdfplumber no está instalado. Instalando...")
    os.system("pip install pdfplumber")
    import pdfplumber

from cai.sdk.agents import Runner, Agent, OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI
from cai.sdk.agents import function_tool

# Importar entidades de dominio
from ...domain.entities import Report, Vulnerability, SeverityLevel, VulnerabilityStatus, ConfidenceLevel
from ...domain.repositories import ReportRepository, VulnerabilityRepository


class PDFTextExtractor:
    """Extractor de texto de archivos PDF usando múltiples métodos"""
    
    @staticmethod
    def extract_with_pdfplumber(pdf_path: str) -> str:
        """Extrae texto usando pdfplumber (mejor para tablas y formato)"""
        text = ""
        try:
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n\n"
        except Exception as e:
            print(f"Error con pdfplumber: {e}")
        return text
    
    @staticmethod
    def extract_with_pypdf2(pdf_path: str) -> str:
        """Extrae texto usando PyPDF2 (fallback)"""
        text = ""
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n\n"
        except Exception as e:
            print(f"Error con PyPDF2: {e}")
        return text
    
    @classmethod
    def extract_text(cls, pdf_path: str) -> str:
        """Extrae texto del PDF usando el mejor método disponible"""
        if not os.path.exists(pdf_path):
            raise FileNotFoundError(f"El archivo {pdf_path} no existe")
        
        # Intentar primero con pdfplumber
        text = cls.extract_with_pdfplumber(pdf_path)
        
        # Si no funciona, usar PyPDF2
        if not text.strip():
            text = cls.extract_with_pypdf2(pdf_path)
        
        return text.strip()


@function_tool
def extract_pdf_text(pdf_path: str) -> str:
    """Función para extraer texto de un archivo PDF"""
    try:
        extractor = PDFTextExtractor()
        text = extractor.extract_text(pdf_path)
        return text if text else "No se pudo extraer texto del PDF"
    except Exception as e:
        return f"Error al extraer texto: {str(e)}"





class ReportReaderAgent:
    """Agente especializado en leer reportes de seguridad y convertir a entidades de dominio"""
    
    def __init__(self, report_repository: ReportRepository, vulnerability_repository: VulnerabilityRepository):
        self.report_repository = report_repository
        self.vulnerability_repository = vulnerability_repository
        
        self.agent = Agent(
            name="Report Reader Agent",
            description="Agente especializado en análisis de reportes de seguridad PDF",
            instructions="""
            Eres un experto en ciberseguridad especializado en análisis de reportes de penetration testing.
            
            Tu tarea es analizar el texto extraído de reportes PDF y estructurar la información en formato JSON.
            
            Debes identificar y extraer:
            
            1. **Información General del Reporte:**
               - Título del reporte
               - Fecha de ejecución
               - Empresa/cliente
               - Consultora que realizó el test
               - Versión del reporte
            
            2. **Scope del Penetration Test:**
               - URLs/dominios objetivo
               - Rangos de IP
               - Aplicaciones específicas
               - Limitaciones del scope
            
            3. **Credenciales y Accesos:**
               - Usuarios de prueba proporcionados
               - Niveles de acceso
               - Credenciales específicas (sin exponer passwords completos)
            
            4. **Vulnerabilidades Encontradas:**
               Para cada vulnerabilidad:
               - Nombre/título de la vulnerabilidad
               - Severidad (Critical, High, Medium, Low, Info)
               - Descripción técnica
               - Pasos de explotación
               - Impacto potencial
               - Recomendaciones de remediación
               - CVE si aplica
               - CVSS score si está disponible
            
            5. **Resumen Ejecutivo:**
               - Número total de vulnerabilidades por severidad
               - Principales hallazgos
               - Recomendaciones generales
            
            6. **Metodología:**
               - Herramientas utilizadas
               - Técnicas empleadas
               - Estándares seguidos (OWASP, NIST, etc.)
            
            IMPORTANTE: 
            - Estructura toda la información en formato JSON válido para procesamiento
            - No inventes información que no esté en el texto
            - Si alguna sección no está presente, marca como "No especificado"
            - Mantén la precisión técnica de los términos de seguridad
            - Organiza las vulnerabilidades por severidad (de mayor a menor)
            - La información será almacenada directamente en MongoDB
            """,
            tools=[
                extract_pdf_text,
            ],
            model=OpenAIChatCompletionsModel(
                model=os.getenv('CAI_MODEL', "gpt-5-nano"),
                openai_client=AsyncOpenAI(),
            )
        )
    
    async def process_pdf_report(self, pdf_path: str) -> Report:
        """Procesa un reporte PDF y retorna una entidad Report con vulnerabilidades"""
        
        prompt = f"""
        Analiza el siguiente reporte de seguridad PDF y extrae toda la información relevante:
        
        1. Primero, extrae el texto del archivo PDF: {pdf_path}
        2. Analiza el contenido y estructura la información en formato JSON
        
        El JSON debe seguir esta estructura:
        {{
            "report_info": {{
                "title": "string",
                "date": "string",
                "client": "string",
                "consultant": "string",
                "version": "string"
            }},
            "scope": {{
                "targets": ["list of URLs/IPs"],
                "applications": ["list of applications"],
                "limitations": "string"
            }},
            "credentials": {{
                "test_accounts": ["list of test users":"passwords"],
                "access_levels": ["list of access levels":"passwords"]
            }},
            "vulnerabilities": [
                {{
                    "name": "string",
                    "type": "string",
                    "severity": "Critical|High|Medium|Low|Info",
                    "description": "string",
                    "exploitation_steps": "string",
                    "impact": "string",
                    "remediation": "string",
                    "cve": "string or null",
                    "cvss_score": "number or null"
                }}
            ],
            "executive_summary": {{
                "total_vulnerabilities": {{
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }},
                "key_findings": ["list of main findings"],
                "recommendations": ["list of general recommendations"]
            }},
            "methodology": {{
                "tools_used": ["list of tools"],
                "techniques": ["list of techniques"],
                "standards": ["list of standards"]
            }}
        }}
        
        Procede con el análisis.
        """
        
        result = await Runner.run(self.agent, prompt)
        print("\nAnálisis del reporte completado:")
        print(result.final_output)
        
        # Cargar el JSON generado y convertir a entidades de dominio
        try:
            # Extraer JSON del output del agente
            output = result.final_output
            # Buscar JSON en el output
            json_start = output.find('{')
            json_end = output.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = output[json_start:json_end]
                data = json.loads(json_str)
            else:
                data = None
            
            if data:
                # Crear entidad Report
                report = self._create_report_entity(data, pdf_path)
                
                # Guardar el reporte en MongoDB
                await self.report_repository.save(report)
                
                # Crear y guardar vulnerabilidades
                vulnerabilities = self._create_vulnerability_entities(data, report.id)
                for vuln in vulnerabilities:
                    await self.vulnerability_repository.save(vuln)
                
                return report
            else:
                raise Exception("No se pudo extraer JSON válido del resultado")
                
        except Exception as e:
            print(f"Error al procesar el JSON generado: {e}")
            raise
        
        raise Exception("No se pudo generar el análisis JSON")
    
    def _create_report_entity(self, data: Dict[str, Any], pdf_path: str) -> Report:
        """Convierte los datos JSON a una entidad Report"""
        report_info = data.get("report_info", {})
        scope = data.get("scope", {})
        credentials = data.get("credentials", {})
        executive_summary = data.get("executive_summary", {})
        methodology = data.get("methodology", {})
        
        return Report(
            id=str(uuid.uuid4()),
            title=report_info.get("title", "Reporte de Seguridad"),
            file_path=pdf_path,
            client=report_info.get("client", "No especificado"),
            consultant=report_info.get("consultant", "No especificado"),
            version=report_info.get("version", "1.0"),
            targets=scope.get("targets", []),
            applications=scope.get("applications", []),
            limitations=scope.get("limitations", ""),
            test_accounts=credentials.get("test_accounts", {}),
            access_levels=credentials.get("access_levels", []),
            tools_used=methodology.get("tools_used", []),
            techniques=methodology.get("techniques", []),
            standards=methodology.get("standards", []),
            key_findings=executive_summary.get("key_findings", []),
            general_recommendations=executive_summary.get("recommendations", []),
            created_at=datetime.utcnow(),
            report_date=datetime.utcnow(),  # TODO: Parse from report_info.date
            processed_at=datetime.utcnow()
        )
    
    def _create_vulnerability_entities(self, data: Dict[str, Any], report_id: str) -> List[Vulnerability]:
        """Convierte los datos JSON a entidades Vulnerability"""
        vulnerabilities = []
        vuln_data_list = data.get("vulnerabilities", [])
        
        for vuln_data in vuln_data_list:
            # Mapear severidad
            severity_str = vuln_data.get("severity", "Info").lower()
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO
            }
            severity = severity_map.get(severity_str, SeverityLevel.INFO)
            
            vulnerability = Vulnerability(
                id=str(uuid.uuid4()),
                name=vuln_data.get("name", "Vulnerabilidad sin nombre"),
                vulnerability_type=vuln_data.get("type", "Unknown"),
                description=vuln_data.get("description", ""),
                severity=severity,
                status=VulnerabilityStatus.VULNERABLE,
                confidence=ConfidenceLevel.MEDIUM,
                evidence=[],
                exploitation_steps=vuln_data.get("exploitation_steps", ""),
                impact=vuln_data.get("impact", ""),
                remediation=vuln_data.get("remediation", ""),
                mitigation_recommendations=[],
                cve=vuln_data.get("cve"),
                cvss_score=vuln_data.get("cvss_score"),
                sources=[f"report:{report_id}"],
                report_id=report_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            # Calcular prioridad basada en severidad y confianza
            vulnerability.priority = vulnerability.calculate_priority()
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities


async def main():
    """Función principal para probar el agente"""
    
    # Configurar conexión a MongoDB
    from ..database import MongoDBConnection
    from ..mongodb_repositories import MongoReportRepository, MongoVulnerabilityRepository
    
    # Inicializar conexión a MongoDB
    db_connection = MongoDBConnection()
    await db_connection.connect()
    
    # Crear repositorios
    report_repo = MongoReportRepository(db_connection)
    vuln_repo = MongoVulnerabilityRepository(db_connection)
    
    # Configurar el agente
    set_tracing_disabled(True)
    reader_agent = ReportReaderAgent(report_repo, vuln_repo)
    
    # Ruta del PDF de ejemplo (ajustar según sea necesario)
    pdf_path = "testing-assets/report.pdf"
    
    if not os.path.exists(pdf_path):
        print(f"Archivo PDF no encontrado: {pdf_path}")
        print("Por favor, proporciona la ruta correcta al archivo PDF.")
        await db_connection.close()
        return
    
    print(f"Procesando reporte: {pdf_path}")
    
    try:
        # Procesar el reporte
        report = await reader_agent.process_pdf_report(pdf_path)
        
        print("\n" + "="*50)
        print("RESULTADO DEL ANÁLISIS:")
        print("="*50)
        print(f"ID: {report.id}")
        print(f"Título: {report.title}")
        print(f"Cliente: {report.client}")
        print(f"Fecha de procesamiento: {report.processed_at}")
        
        # Obtener vulnerabilidades asociadas
        vulnerabilities = await vuln_repo.find_by_source(f"report:{report.id}")
        print(f"\nVulnerabilidades encontradas: {len(vulnerabilities)}")
        for vuln in vulnerabilities:
            print(f"- {vuln.name} ({vuln.severity.value})")
            
    except Exception as e:
        print(f"Error al procesar el reporte: {e}")
    
    # Cerrar conexión
    await db_connection.close()


if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
Static Analysis Agent - Valida vulnerabilidades en código fuente usando análisis estático

Este agente se encarga de:
- Leer vulnerabilidades desde MongoDB
- Ejecutar semgrep para escaneo global de vulnerabilidades
- Analizar archivos relevantes para buscar evidencia de cada vulnerabilidad
- Actualizar el estado de las vulnerabilidades en MongoDB
"""

import os
import sys
import json
import asyncio
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import uuid

from cai.sdk.agents import Runner, Agent, OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI
from cai.sdk.agents import function_tool
from cai.tools.common import run_command

# Importar entidades de dominio y repositorios
from ...domain.entities import Vulnerability, VulnerabilityStatus, ConfidenceLevel, Analysis, AnalysisType
from ...domain.repositories import VulnerabilityRepository, AnalysisRepository


@function_tool
def execute_command(command: str) -> str:
    """Ejecuta un comando del sistema y retorna el resultado"""
    try:
        result = run_command(command)
        return result
    except Exception as e:
        return f"Error ejecutando comando: {str(e)}"


@function_tool
def read_json_file(file_path: str) -> str:
    """Lee un archivo JSON y retorna su contenido como string"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except FileNotFoundError:
        return f"Error: Archivo {file_path} no encontrado"
    except json.JSONDecodeError as e:
        return f"Error: JSON inválido en {file_path} - {str(e)}"
    except Exception as e:
        return f"Error leyendo archivo: {str(e)}"


@function_tool
def read_file_content(file_path: str) -> str:
    """Lee el contenido de un archivo de texto"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return f"Error: Archivo {file_path} no encontrado"
    except Exception as e:
        return f"Error leyendo archivo: {str(e)}"


@function_tool
def run_semgrep_scan(target_directory: str) -> str:
    """Ejecuta semgrep con configuración automática en el directorio objetivo"""
    try:
        # Comando semgrep con configuración automática
        command = f"semgrep --config=auto --json --output=/tmp/semgrep_results.json {target_directory}"
        result = run_command(command)
        
        # Leer los resultados JSON
        try:
            with open('/tmp/semgrep_results.json', 'r') as f:
                semgrep_data = json.load(f)
            return json.dumps(semgrep_data, indent=2)
        except:
            return result  # Retornar output directo si no hay JSON
            
    except Exception as e:
        return f"Error ejecutando semgrep: {str(e)}"


@function_tool
def save_validation_results(results_json: str, output_path: str = "static_agent_results.json") -> str:
    """Guarda los resultados de validación en un archivo JSON"""
    try:
        # Validar que sea JSON válido
        parsed_data = json.loads(results_json)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, indent=2, ensure_ascii=False)
        
        return f"Resultados de validación guardados en: {output_path}"
    except json.JSONDecodeError as e:
        return f"Error: JSON inválido - {str(e)}"
    except Exception as e:
        return f"Error al guardar archivo: {str(e)}"


class StaticAnalysisAgent:
    """Agente especializado en validación de vulnerabilidades mediante análisis estático"""
    
    def __init__(self, vulnerability_repository: VulnerabilityRepository, analysis_repository: AnalysisRepository):
        self.vulnerability_repository = vulnerability_repository
        self.analysis_repository = analysis_repository
        
        self.agent = Agent(
            name="Static Analysis Agent",
            description="Agente especializado en validación de vulnerabilidades usando análisis estático",
            instructions="""
            Eres un experto en ciberseguridad especializado en análisis estático de código y validación de vulnerabilidades.
            
            Tu tarea es validar la existencia de vulnerabilidades reportadas mediante análisis del código fuente.
            
            PROCESO DE VALIDACIÓN:
            
            1. **Escaneo Global con Semgrep:**
               - Ejecuta semgrep con configuración automática en el directorio objetivo
               - Analiza los resultados para identificar patrones de vulnerabilidades
            
            2. **Análisis Individual por Vulnerabilidad:**
               Para cada vulnerabilidad:
               - Analiza archivos relevantes del código fuente
               - Busca evidencia específica de la vulnerabilidad
               - Determina el estado: "vulnerable" o "not_vulnerable"
               - Calcula nivel de confianza: "HIGH", "MEDIUM", "LOW"
               - Recopila evidencia encontrada
            
            3. **Generación de Resultados:**
               Para cada vulnerabilidad, genera un JSON con esta estructura:
               {
                   "vulnerability_id": "ID de la vulnerabilidad",
                   "status": "vulnerable|not_vulnerable",
                   "evidence": ["lista de evidencias encontradas"],
                   "confidence": "HIGH|MEDIUM|LOW",
                   "analysis_summary": "resumen del análisis",
                   "patterns_checked": "número de patrones verificados",
                   "files_analyzed": ["lista de archivos analizados"]
               }
            
            CRITERIOS DE VALIDACIÓN:
            - HIGH confidence: Evidencia directa en el código, patrones claros
            - MEDIUM confidence: Indicios fuertes pero no definitivos
            - LOW confidence: Posibles indicios, requiere validación manual
            
            HERRAMIENTAS DISPONIBLES:
            - execute_command: Para ejecutar comandos del sistema
            - read_file_content: Para leer archivos de código
            - run_semgrep_scan: Para ejecutar análisis con semgrep
            
            
            IMPORTANTE:
            - Sé preciso en tu análisis y no hagas suposiciones
            - Documenta toda la evidencia encontrada
            - Usa semgrep y análisis manual del código
            - Mantén la trazabilidad entre el reporte original y tus hallazgos
            
            Siempre proporciona análisis detallados y evidencia específica.
            """,
            tools=[
                execute_command,
                read_json_file,
                read_file_content,
                run_semgrep_scan,
                save_validation_results,
            ],
            model=OpenAIChatCompletionsModel(
                model=os.getenv('CAI_MODEL', "gpt-5-nanoo"),
                openai_client=AsyncOpenAI(),
            )
        )
    
    async def validate_vulnerabilities(self, vulnerabilities: List[Vulnerability], source_directory: str) -> List[Analysis]:
        """Valida las vulnerabilidades contra el código fuente y retorna análisis"""
        
        analyses = []
        
        for vulnerability in vulnerabilities:
            prompt = f"""
            Valida la siguiente vulnerabilidad en el código fuente:
            
            **VULNERABILIDAD A VALIDAR:**
            - ID: {vulnerability.id}
            - Nombre: {vulnerability.name}
            - Tipo: {vulnerability.vulnerability_type}
            - Severidad: {vulnerability.severity.value}
            - Descripción: {vulnerability.description}
            
            **DIRECTORIO DE CÓDIGO:** {source_directory}
            
            **PROCESO DE VALIDACIÓN:**
            
            1. **Ejecuta semgrep para escaneo global** en el directorio
            
            2. **Analiza archivos relevantes** para buscar evidencia específica de esta vulnerabilidad
            
            3. **Determina el estado de validación:**
               - "vulnerable": Si encuentras evidencia clara de la vulnerabilidad
               - "not_vulnerable": Si no encuentras evidencia o está mitigada
            
            4. **Calcula el nivel de confianza:**
               - "HIGH": Evidencia directa y clara
               - "MEDIUM": Indicios fuertes pero no definitivos
               - "LOW": Posibles indicios, requiere validación manual
            
            5. **Recopila evidencia encontrada** (archivos, líneas de código, patrones)
            
            6. **Genera un JSON con los resultados** siguiendo esta estructura:
            {{
                "vulnerability_id": "{vulnerability.id}",
                "status": "vulnerable|not_vulnerable",
                "evidence": ["lista de evidencias encontradas"],
                "confidence": "HIGH|MEDIUM|LOW",
                "analysis_summary": "resumen detallado del análisis",
                "patterns_checked": "número de patrones verificados",
                "files_analyzed": ["lista de archivos analizados"]
            }}
            
            Procede con la validación de esta vulnerabilidad específica.
            """
            
            result = await Runner.run(self.agent, prompt)
            print(f"\nValidación completada para: {vulnerability.name}")
            print(result.final_output)
            
            # Crear análisis basado en el resultado
            analysis = self._create_analysis_from_result(vulnerability, result.final_output, source_directory)
            analyses.append(analysis)
            
            # Guardar análisis en MongoDB
            await self.analysis_repository.save(analysis)
            
            # Actualizar estado de la vulnerabilidad si es necesario
            if "vulnerable" in result.final_output.lower():
                vulnerability.status = VulnerabilityStatus.VULNERABLE
            else:
                vulnerability.status = VulnerabilityStatus.NOT_VULNERABLE
            
            vulnerability.updated_at = datetime.utcnow()
            await self.vulnerability_repository.update(vulnerability)
        
        return analyses
    
    def _create_analysis_from_result(self, vulnerability: Vulnerability, result_output: str, source_directory: str) -> Analysis:
        """Crea una entidad Analysis a partir del resultado del agente"""
        
        # Extraer información del resultado (simplificado)
        is_vulnerable = "vulnerable" in result_output.lower() and "not_vulnerable" not in result_output.lower()
        
        # Determinar confianza basada en palabras clave
        confidence = ConfidenceLevel.MEDIUM
        if "high confidence" in result_output.lower() or "evidencia clara" in result_output.lower():
            confidence = ConfidenceLevel.HIGH
        elif "low confidence" in result_output.lower() or "posibles indicios" in result_output.lower():
            confidence = ConfidenceLevel.LOW
        
        return Analysis(
            analysis_type=AnalysisType.STATIC_ANALYSIS,
            agent_name="static_analysis_agent",
            id=str(uuid.uuid4()),
            vulnerability_ids=[vulnerability.id],
            source_directory=source_directory,
            context={
                "vulnerability_name": vulnerability.name,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "agent_version": "1.0",
                "evidence": [result_output],
                "confidence": confidence.value,
                "is_vulnerable": is_vulnerable
            }
        )


async def main():
    """Función principal para probar el agente"""
    
    # Configurar conexión a MongoDB
    from ..database import MongoDBConnection
    from ..mongodb_repositories import MongoVulnerabilityRepository, MongoAnalysisRepository
    
    # Inicializar conexión a MongoDB
    db_connection = MongoDBConnection()
    await db_connection.connect()
    
    # Crear repositorios
    vuln_repo = MongoVulnerabilityRepository(db_connection)
    analysis_repo = MongoAnalysisRepository(db_connection)
    
    # Configurar el agente
    set_tracing_disabled(True)
    static_agent = StaticAnalysisAgent(vuln_repo, analysis_repo)
    
    # Directorio del código fuente a analizar
    source_directory = "testing-assets/vuln-app-main"
    
    if not os.path.exists(source_directory):
        print(f"Directorio de código fuente no encontrado: {source_directory}")
        print("Por favor, proporciona la ruta correcta al código fuente.")
        await db_connection.close()
        return
    
    print(f"Validando vulnerabilidades en: {source_directory}")
    
    try:
        # Obtener vulnerabilidades pendientes de validación
        vulnerabilities = await vuln_repo.find_by_status(VulnerabilityStatus.IDENTIFIED)
        
        if not vulnerabilities:
            print("No se encontraron vulnerabilidades pendientes de validación.")
            await db_connection.close()
            return
        
        print(f"Encontradas {len(vulnerabilities)} vulnerabilidades para validar:")
        for vuln in vulnerabilities:
            print(f"- {vuln.name} ({vuln.severity.value})")
        
        # Validar vulnerabilidades
        analyses = await static_agent.validate_vulnerabilities(vulnerabilities, source_directory)
        
        print(f"\n{'='*50}")
        print("RESULTADOS DE VALIDACIÓN:")
        print("="*50)
        
        for analysis in analyses:
            vuln = next(v for v in vulnerabilities if v.id == analysis.vulnerability_id)
            print(f"\nVulnerabilidad: {vuln.name}")
            print(f"Estado: {analysis.status.value}")
            print(f"Confianza: {analysis.confidence.value}")
            print(f"Resumen: {analysis.analysis_summary}")
            
    except Exception as e:
        print(f"Error durante la validación: {e}")
    
    # Cerrar conexión
    await db_connection.close()

if __name__ == "__main__":
    asyncio.run(main())
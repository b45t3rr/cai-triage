#!/usr/bin/env python3
"""
Static Analysis Agent - Valida vulnerabilidades en código fuente usando análisis estático

Este agente se encarga de:
- Leer vulnerabilidades desde report_analysis.json
- Ejecutar semgrep para escaneo global de vulnerabilidades
- Analizar archivos relevantes para buscar evidencia de cada vulnerabilidad
- Generar un JSON de validación con resultados detallados
"""

import os
import sys
import json
import asyncio
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from cai.sdk.agents import Runner, Agent, OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI
from cai.sdk.agents import function_tool
from cai.tools.common import run_command


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
    
    def __init__(self):
        self.agent = Agent(
            name="Static Analysis Agent",
            description="Agente especializado en validación de vulnerabilidades usando análisis estático",
            instructions="""
            Eres un experto en ciberseguridad especializado en análisis estático de código y validación de vulnerabilidades.
            
            Tu tarea es validar la existencia de vulnerabilidades reportadas mediante análisis del código fuente.
            
            PROCESO DE VALIDACIÓN:
            
            1. **Lectura de Vulnerabilidades:**
               - Lee el archivo report_analysis.json para obtener las vulnerabilidades reportadas
               - Extrae información clave: nombre, tipo, severidad, descripción
            
            2. **Escaneo Global con Semgrep:**
               - Ejecuta semgrep con configuración automática en el directorio objetivo
               - Analiza los resultados para identificar patrones de vulnerabilidades
            
            3. **Análisis Individual por Vulnerabilidad:**
               Para cada vulnerabilidad del reporte:
               - Analiza archivos relevantes del código fuente
               - Busca evidencia específica de la vulnerabilidad
               - Determina el estado: "vulnerable" o "not_vulnerable"
               - Calcula nivel de confianza: "HIGH", "MEDIUM", "LOW"
               - Recopila evidencia encontrada
            
            4. **Generación de Resultados:**
               Para cada vulnerabilidad, genera un JSON con esta estructura:
               {
                   "vulnerability_name": "nombre de la vulnerabilidad",
                   "vulnerability_type": "tipo de vulnerabilidad",
                   "original_severity": "severidad original",
                   "description": "descripción de la vulnerabilidad",
                   "status": "vulnerable|not_vulnerable",
                   "evidence": ["lista de evidencias encontradas"],
                   "confidence": "HIGH|MEDIUM|LOW",
                   "analysis_summary": "resumen del análisis",
                   "validation_context": {
                       "source_directory": "directorio analizado",
                       "analysis_timestamp": "timestamp ISO",
                       "patterns_checked": "número de patrones verificados"
                   }
               }
            
            CRITERIOS DE VALIDACIÓN:
            
            - **vulnerable (HIGH confidence):** Evidencia clara y directa de la vulnerabilidad
            - **vulnerable (MEDIUM confidence):** Evidencia parcial o patrones similares que confirman la vulnerabilidad
            - **vulnerable (LOW confidence):** Indicios que sugieren la presencia de la vulnerabilidad
            - **not_vulnerable (HIGH confidence):** No se encontró evidencia tras análisis exhaustivo
            - **not_vulnerable (MEDIUM confidence):** Evidencia sugiere que la vulnerabilidad fue mitigada o no existe
            - **not_vulnerable (LOW confidence):** Análisis inconcluso pero sin evidencia clara de vulnerabilidad
            
            IMPORTANTE:
            - Sé preciso en tu análisis y no hagas suposiciones
            - Documenta toda la evidencia encontrada
            - Usa semgrep y análisis manual del código
            - Mantén la trazabilidad entre el reporte original y tus hallazgos
            """,
            tools=[
                execute_command,
                read_json_file,
                read_file_content,
                run_semgrep_scan,
                save_validation_results,
            ],
            model=OpenAIChatCompletionsModel(
                model=os.getenv('CAI_MODEL', "gpt-5-nano"),
                openai_client=AsyncOpenAI(),
            )
        )
    
    async def validate_vulnerabilities(self, source_directory: str, report_json_path: str = "report_analysis.json") -> Dict[str, Any]:
        """Valida las vulnerabilidades del reporte contra el código fuente"""
        
        prompt = f"""
        Valida las vulnerabilidades reportadas en el código fuente siguiendo este proceso:
        
        1. **Lee las vulnerabilidades del reporte:** {report_json_path}
        
        2. **Ejecuta semgrep para escaneo global:** {source_directory}
        
        3. **Para cada vulnerabilidad del reporte:**
           - Analiza archivos relevantes en: {source_directory}
           - Busca evidencia específica de la vulnerabilidad
           - Determina el estado de validación
           - Calcula el nivel de confianza
           - Recopila evidencia encontrada
        
        4. **Genera el JSON de resultados** con la estructura especificada para cada vulnerabilidad
        
        5. **Guarda los resultados** en static_agent_results.json
        
        Procede con la validación completa.
        """
        
        result = await Runner.run(self.agent, prompt)
        print("\nValidación de vulnerabilidades completada:")
        print(result.final_output)
        
        # Intentar cargar el JSON de resultados generado
        try:
            results_file = "static_agent_results.json"
            if os.path.exists(results_file):
                with open(results_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error al cargar los resultados generados: {e}")
        
        return {"error": "No se pudieron generar los resultados de validación"}


async def main():
    """Función principal para probar el agente"""
    # Configurar el agente
    set_tracing_disabled(True)
    
    # Crear instancia del agente
    static_agent = StaticAnalysisAgent()
    
    # Directorio del código fuente a analizar
    source_directory = "testing-assets/vuln-app-main"
    report_json = "report_analysis.json"
    
    if not os.path.exists(source_directory):
        print(f"Directorio de código fuente no encontrado: {source_directory}")
        print("Por favor, proporciona la ruta correcta al código fuente.")
        return
    
    if not os.path.exists(report_json):
        print(f"Archivo de reporte no encontrado: {report_json}")
        print("Por favor, asegúrate de que existe el archivo report_analysis.json.")
        return
    
    print(f"Validando vulnerabilidades en: {source_directory}")
    print(f"Usando reporte: {report_json}")
    
    # Validar vulnerabilidades
    result = await static_agent.validate_vulnerabilities(source_directory, report_json)
    
    print("\n" + "="*50)
    print("RESULTADO DE LA VALIDACIÓN:")
    print("="*50)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
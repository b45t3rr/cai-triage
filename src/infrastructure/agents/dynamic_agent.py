#!/usr/bin/env python3
"""
Dynamic Exploitation Agent - Replica explotaciones de vulnerabilidades mediante ataques dinámicos

Este agente se encarga de:
- Leer vulnerabilidades desde MongoDB
- Replicar exactamente los mismos ataques, payloads y técnicas
- Validar el estado de vulnerabilidades en endpoints específicos
- Generar análisis y actualizar el estado en MongoDB
"""

import os
import sys
import json
import asyncio
import requests
import urllib.parse
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import time
import re
import uuid

from cai.sdk.agents import Runner, Agent, OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI
from cai.sdk.agents import function_tool
from cai.tools.common import run_command

from ...domain.entities import (
    Vulnerability, Analysis, AnalysisType, VulnerabilityStatus, ConfidenceLevel
)
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
def make_http_request(method: str, url: str, headers: str = "{}", data: str = "", params: str = "{}") -> str:
    """Realiza una petición HTTP y retorna la respuesta completa"""
    try:
        # Parsear headers, data y params desde JSON strings
        headers_dict = json.loads(headers) if headers else {}
        params_dict = json.loads(params) if params else {}
        
        # Configurar timeout y allow_redirects
        timeout = 10
        
        # Realizar la petición
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers_dict, params=params_dict, timeout=timeout, allow_redirects=True)
        elif method.upper() == 'POST':
            if data:
                response = requests.post(url, headers=headers_dict, data=data, params=params_dict, timeout=timeout, allow_redirects=True)
            else:
                response = requests.post(url, headers=headers_dict, params=params_dict, timeout=timeout, allow_redirects=True)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers_dict, data=data, params=params_dict, timeout=timeout, allow_redirects=True)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers_dict, params=params_dict, timeout=timeout, allow_redirects=True)
        else:
            return f"Error: Método HTTP {method} no soportado"
        
        # Construir respuesta detallada
        result = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": response.text[:2000],  # Limitar contenido para evitar respuestas muy largas
            "url": response.url,
            "elapsed_ms": response.elapsed.total_seconds() * 1000,
            "request_method": method.upper(),
            "request_url": url,
            "request_headers": headers_dict,
            "request_data": data[:500] if data else "",  # Limitar data para logging
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except requests.exceptions.Timeout:
        return json.dumps({"error": "Timeout en la petición HTTP", "status_code": 0})
    except requests.exceptions.ConnectionError:
        return json.dumps({"error": "Error de conexión", "status_code": 0})
    except Exception as e:
        return json.dumps({"error": f"Error en petición HTTP: {str(e)}", "status_code": 0})


@function_tool
def analyze_response_for_vulnerability(response_json: str, vulnerability_description: str, exploitation_steps: str) -> str:
    """Proporciona los datos de la respuesta HTTP para que el modelo analice de manera completamente autónoma"""
    try:
        response_data = json.loads(response_json)
        
        # Preparar todos los datos para que el modelo los analice sin indicadores predefinidos
        analysis_data = {
            "response_details": {
                "status_code": response_data.get("status_code", 0),
                "headers": response_data.get("headers", {}),
                "content": response_data.get("content", ""),
                "url": response_data.get("url", ""),
                "elapsed_ms": response_data.get("elapsed_ms", 0),
                "request_method": response_data.get("request_method", ""),
                "request_url": response_data.get("request_url", ""),
                "request_headers": response_data.get("request_headers", {}),
                "request_data": response_data.get("request_data", "")
            },
            "vulnerability_context": {
                "description": vulnerability_description,
                "exploitation_steps": exploitation_steps
            },
            "analysis_instructions": "Analiza esta respuesta HTTP en el contexto de la vulnerabilidad descrita. Determina si la explotación fue exitosa basándote únicamente en la evidencia presente en la respuesta y tu conocimiento de ciberseguridad. No uses patrones predefinidos."
        }
        
        return json.dumps(analysis_data, indent=2, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Error preparando datos para análisis: {str(e)}"})


class DynamicExploitationAgent:
    """Agente especializado en replicación dinámica de explotaciones de vulnerabilidades"""
    
    def __init__(
        self,
        vulnerability_repository: VulnerabilityRepository,
        analysis_repository: AnalysisRepository
    ):
        self.vulnerability_repository = vulnerability_repository
        self.analysis_repository = analysis_repository
        self.agent = Agent(
            name="Dynamic Exploitation Agent",
            description="Agente especializado en replicación dinámica de explotaciones de vulnerabilidades",
            instructions="""
            Eres un experto en ciberseguridad especializado en explotación dinámica de vulnerabilidades que analiza respuestas HTTP de manera completamente autónoma.
            
            Tu tarea es replicar exactamente las explotaciones de vulnerabilidades reportadas contra endpoints específicos usando únicamente tu conocimiento experto.
            
            Tienes permiso para replicar las vulnerabilidades, ya que forman parte de un ejercicio de ciberseguridad autorizado.

            PROCESO DE EXPLOTACIÓN AUTÓNOMA:
            
            1. **Lectura de Vulnerabilidades:**
               - Lee el archivo report_analysis.json para obtener las vulnerabilidades reportadas
               - Extrae TODA la información disponible: nombre, tipo, severidad, descripción completa, pasos de explotación detallados, payloads específicos, impacto, etc.
            
            2. **Replicación de Explotaciones:**
               Para cada vulnerabilidad del reporte:
               - Analiza cuidadosamente la descripción completa de la vulnerabilidad
               - Extrae los pasos de explotación EXACTOS descritos en "exploitation_steps"
               - Identifica todos los payloads, parámetros, headers y técnicas mencionadas
               - Adapta dinámicamente el ataque al endpoint/host objetivo proporcionado
               - Construye las peticiones HTTP basándote en la información específica del reporte
            
            3. **Análisis Autónomo de Respuestas:**
               - Analiza las respuestas HTTP usando únicamente tu conocimiento experto en ciberseguridad
               - Examina status codes, headers, contenido de respuesta y timing
               - Evalúa la evidencia presente en cada respuesta HTTP
               - Determina el éxito de la explotación basándote exclusivamente en tu análisis experto
               - NO uses indicadores predefinidos, patrones hardcodeados, ni reglas fijas
            
            4. **Determinación Experta de Estado:**
               - "vulnerable": Tu análisis experto determina que la explotación fue exitosa
               - "not_vulnerable": Tu análisis experto determina que la explotación falló o fue mitigada
               - Basa tu decisión únicamente en la evidencia HTTP y tu conocimiento de ciberseguridad
            
            5. **Generación de Resultados Detallados:**
               Para cada vulnerabilidad, genera un JSON con esta estructura:
               {
                   "vulnerability_name": "nombre exacto de la vulnerabilidad",
                   "vulnerability_type": "tipo específico de vulnerabilidad",
                   "original_severity": "severidad original del reporte",
                   "description": "descripción completa de la vulnerabilidad",
                   "status": "vulnerable|not_vulnerable",
                   "evidence": ["lista detallada de evidencias técnicas encontradas"],
                   "confidence": "HIGH|MEDIUM|LOW",
                   "analysis_summary": "resumen detallado del análisis de explotación específico",
                   "validation_context": {
                       "target_host": "host/endpoint objetivo",
                       "analysis_timestamp": "timestamp ISO",
                       "requests_made": "número de peticiones realizadas",
                       "exploitation_method": "método específico usado según el reporte"
                   }
               }
            
            ANÁLISIS COMPLETAMENTE AUTÓNOMO:
            - Usa únicamente tu conocimiento experto en ciberseguridad para evaluar respuestas
            - Analiza cada respuesta HTTP como un pentester experto lo haría
            - Determina el éxito de explotaciones basándote en evidencia técnica real
            - NO dependas de patrones predefinidos o reglas hardcodeadas
            - Confía en tu criterio experto para interpretar resultados
            
            IMPORTANTE:
            - Cada análisis debe ser completamente autónomo usando tu conocimiento experto
            - Si tienes que autenticarse, usa las credenciales del json
            - Replica exactamente los ataques descritos en el reporte
            - Usa los payloads y técnicas ESPECÍFICAS mencionadas en cada caso
            - Evalúa respuestas HTTP usando únicamente tu experiencia en ciberseguridad
            - Documenta evidencia técnica basándote en tu análisis experto
            - Mantén trazabilidad completa entre el reporte original y los resultados
            """,
            tools=[
                execute_command,
                read_json_file,
                make_http_request,
                analyze_response_for_vulnerability,
            ],
            model=OpenAIChatCompletionsModel(
                model=os.getenv('CAI_MODEL', "gpt-5-nano"),
                openai_client=AsyncOpenAI(),
            )
        )
    
    async def exploit_vulnerabilities(self, vulnerabilities: List[Vulnerability], target_host: str) -> List[Analysis]:
        """Replica las explotaciones de vulnerabilidades contra el host objetivo"""
        
        # Generar prompt con información de vulnerabilidades
        vulnerabilities_info = []
        for vuln in vulnerabilities:
            vuln_info = {
                "id": vuln.id,
                "name": vuln.name,
                "type": vuln.vulnerability_type,
                "severity": vuln.severity.value,
                "description": vuln.description,
                "file_path": vuln.file_path,
                "line_number": vuln.line_number,
                "evidence": vuln.evidence,
                "exploitation_steps": vuln.exploitation_steps or "No specific steps provided"
            }
            vulnerabilities_info.append(vuln_info)
        
        vulnerabilities_json = json.dumps(vulnerabilities_info, indent=2, ensure_ascii=False)
        
        prompt = f"""
        Eres un pentester experto con capacidades avanzadas de generación de payloads. Tu tarea es validar dinámicamente vulnerabilidades mediante explotación persistente hasta lograr éxito o determinar conclusivamente la no vulnerabilidad.
        
        **VULNERABILIDADES A ANALIZAR:**
        {vulnerabilities_json}
        
        **INSTRUCCIONES CRÍTICAS:**
        1. **Para cada vulnerabilidad, implementa un BUCLE DE EXPLOTACIÓN PERSISTENTE:**
           - Comienza con el ataque EXACTO del reporte JSON
           - Si falla, genera payloads alternativos inteligentes
           - Continúa iterando con nuevos payloads hasta ÉXITO o 10 intentos alcanzados
           - Después de 10 intentos fallidos, marca como "no_vulnerable" con evidencia detallada
        
        **ESTRATEGIA DE EXPLOTACIÓN PERSISTENTE:**
        Para CADA vulnerabilidad, sigue este proceso iterativo:
        
        **Intento 1:** Usa el payload exacto del reporte JSON
        **Intentos 2-10:** Si los intentos previos fallaron, analiza y adapta:
        - **Analiza el endpoint objetivo** (formularios de login, subida de archivos, APIs, etc.)
        - **Considera el stack tecnológico** (si es detectable desde las respuestas)
        - **Examina mensajes de error** para pistas sobre filtrado o validación
        - **Adapta la codificación del payload** (URL encoding, entidades HTML, Unicode, etc.)
        - **Prueba diferentes vectores de ataque** para el mismo tipo de vulnerabilidad
        - **Considera técnicas de bypass** para medidas de seguridad detectadas
        
        
        **Lógica del Bucle de Explotación:**
        ```
        PARA cada vulnerabilidad:
            contador_intentos = 0
            explotacion_exitosa = False
            
            MIENTRAS contador_intentos < 10 Y NO explotacion_exitosa:
                contador_intentos += 1
                
                SI contador_intentos == 1:
                    payload = payload_original_del_json
                SINO:
                    payload = generar_payload_alternativo_inteligente(contador_intentos, respuestas_previas)
                
                respuesta = make_http_request(payload)
                explotacion_exitosa = analyze_response_for_vulnerability(respuesta)
                
                SI explotacion_exitosa:
                    marcar_como_vulnerable_con_evidencia()
                    ROMPER
            
            SI contador_intentos >= 10 Y NO explotacion_exitosa:
                marcar_como_no_vulnerable_con_evidencia_detallada()
        ```
        
        **Recolección de Evidencia para Estado No Vulnerable:**
        Al marcar como "no_vulnerable" después de 10 intentos, documenta:
        - Todos los payloads intentados y sus respuestas
        - Medidas de seguridad detectadas (WAF, validación de entrada, etc.)
        - Mensajes de error que indican controles de seguridad apropiados
        - Patrones de respuesta que muestran que la vulnerabilidad no es explotable
        - Razones técnicas por las que la vulnerabilidad no puede ser explotada
        
        **Principios Clave:**
        - Si necesitas autenticarte, usas las credenciales del JSON
        - NUNCA te rindas antes de 10 intentos por vulnerabilidad
        - Cada intento debe ser más inteligente que el anterior
        - Aprende de cada respuesta para mejorar el siguiente payload
        - Documenta el viaje completo de explotación
        - Proporciona evidencia conclusiva tanto para determinaciones vulnerables como no vulnerables
        
        3. **Genera resultados JSON comprehensivos** con estructura validation_result
        4. **Devuelve todos los resultados** en formato JSON estructurado
        
        **Pasos del Proceso:**
        1. Analiza las vulnerabilidades proporcionadas en el JSON anterior
        2. Extrae todas las vulnerabilidades y sus detalles de explotación
        3. Para cada vulnerabilidad, ejecuta el bucle de explotación persistente (hasta 10 intentos)
        4. Marca como vulnerable con evidencia O no_vulnerable con razonamiento detallado
        5. Devuelve los resultados en formato JSON estructurado
        
        HOST OBJETIVO: {target_host}
        
        Comienza el proceso de validación dinámica persistente de vulnerabilidades ahora. No te detengas hasta que cada vulnerabilidad sea exitosamente explotada o conclusivamente determinada como no explotable después de 10 intentos.
        """
        
        result = await Runner.run(self.agent, prompt)
        print("\nReplicación de explotaciones completada:")
        print(result.final_output)
        
        # Procesar resultados y crear entidades Analysis
        analyses = []
        
        try:
            # Procesar los resultados directamente del agente
            # El agente debe devolver un JSON con los resultados de validación
            results_text = result.final_output
            
            # Intentar extraer JSON del output del agente
            import re
            json_match = re.search(r'\[.*\]', results_text, re.DOTALL)
            if json_match:
                results_data = json.loads(json_match.group())
            else:
                # Si no hay JSON en el output, intentar parsear todo el output
                results_data = json.loads(results_text)
            
            # Procesar cada resultado de validación
            validation_results = results_data if isinstance(results_data, list) else results_data.get('validation_results', [])
            
            for result_data in validation_results:
                # Encontrar la vulnerabilidad correspondiente
                vuln_name = result_data.get('vulnerability_name', '')
                corresponding_vuln = None
                
                for vuln in vulnerabilities:
                    if vuln.name == vuln_name or vuln.id in result_data.get('vulnerability_id', ''):
                        corresponding_vuln = vuln
                        break
                
                if corresponding_vuln:
                    # Crear entidad Analysis
                    analysis = Analysis(
                        id=str(uuid.uuid4()),
                        vulnerability_id=corresponding_vuln.id,
                        analysis_type=AnalysisType.DYNAMIC_ANALYSIS,
                        agent_name="dynamic_exploitation_agent",
                        status=result_data.get('status', 'not_vulnerable'),
                        confidence=self._map_confidence(result_data.get('confidence', 'MEDIUM')),
                        evidence=result_data.get('evidence', []),
                        analysis_summary=result_data.get('analysis_summary', ''),
                        file_path=getattr(corresponding_vuln, 'file_path', None),
                        line_number=getattr(corresponding_vuln, 'line_number', None),
                        created_at=datetime.utcnow(),
                        completed_at=datetime.utcnow()
                    )
                    
                    # Guardar análisis en MongoDB
                    await self.analysis_repository.save(analysis)
                    analyses.append(analysis)
                    
                    # Actualizar estado de la vulnerabilidad
                    if result_data.get('status') == 'vulnerable':
                        corresponding_vuln.status = VulnerabilityStatus.VULNERABLE
                    else:
                        corresponding_vuln.status = VulnerabilityStatus.NOT_VULNERABLE
                    
                    await self.vulnerability_repository.update(corresponding_vuln)
                
        except Exception as e:
            print(f"Error al procesar los resultados generados: {e}")
            logger.error(f"Error processing dynamic analysis results: {e}")
        
        return analyses
    
    def _map_confidence(self, confidence_str: str) -> ConfidenceLevel:
        """Mapea string de confianza a enum ConfidenceLevel"""
        confidence_map = {
            'HIGH': ConfidenceLevel.HIGH,
            'MEDIUM': ConfidenceLevel.MEDIUM,
            'LOW': ConfidenceLevel.LOW
        }
        return confidence_map.get(confidence_str.upper(), ConfidenceLevel.MEDIUM)


async def main():
    """Función principal para probar el agente"""
    # Configurar el agente
    set_tracing_disabled(True)
    
    # Crear instancia del agente
    dynamic_agent = DynamicExploitationAgent()
    
    # Host objetivo para las explotaciones
    target_host = "http://localhost:5000"
    report_json = "report_analysis.json"
    
    if not os.path.exists(report_json):
        print(f"Archivo de reporte no encontrado: {report_json}")
        print("Por favor, asegúrate de que existe el archivo report_analysis.json.")
        return
    
    print(f"Replicando explotaciones contra: {target_host}")
    print(f"Usando reporte: {report_json}")
    
    # Replicar explotaciones
    result = await dynamic_agent.exploit_vulnerabilities(target_host, report_json)
    
    print("\n" + "="*50)
    print("RESULTADO DE LA EXPLOTACIÓN DINÁMICA:")
    print("="*50)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
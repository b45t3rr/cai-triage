#!/usr/bin/env python3
"""
Triage Agent - Consolida y prioriza vulnerabilidades de múltiples fuentes de análisis

Este agente se encarga de:
- Leer vulnerabilidades desde MongoDB
- Detectar y correlacionar vulnerabilidades duplicadas usando análisis semántico con LLM
- Consolidar evidencia de múltiples fuentes
- Asignar severidad y prioridad basada en evidencia consolidada
- Proporcionar recomendaciones de mitigación específicas
- Generar y guardar resultados de triage en MongoDB
"""

import os
import sys
import json
import asyncio
import uuid
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
import hashlib
import re

from cai.sdk.agents import Runner, Agent, OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI
from cai.sdk.agents import function_tool

from ...domain.entities import (
    Vulnerability, Analysis, TriageResult, SeverityLevel,
    VulnerabilityStatus, ConfidenceLevel
)
from ...domain.repositories import (
    VulnerabilityRepository, AnalysisRepository, TriageResultRepository
)

@function_tool
def read_json_file_tool(file_path: str) -> str:
    """Lee un archivo JSON y retorna su contenido como string"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = json.load(f)
            return json.dumps(content, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Error leyendo {file_path}: {e}"

@function_tool
def save_triage_results_tool(results: str) -> str:
    """Procesa y retorna los resultados del triage para ser guardados en MongoDB"""
    try:
        # Parsear el JSON string a dict para validar formato
        results_dict = json.loads(results)
        
        # Validar estructura requerida
        if 'triage_summary' not in results_dict or 'consolidated_vulnerabilities' not in results_dict:
            return "Error: Estructura de resultados inválida. Se requieren 'triage_summary' y 'consolidated_vulnerabilities'"
        
        # Retornar los resultados como JSON string para procesamiento posterior
        return f"TRIAGE_RESULTS_JSON:{results}"
    except Exception as e:
        return f"Error procesando resultados: {e}"

def read_json_file(file_path: str) -> Dict[str, Any]:
    """Lee un archivo JSON y retorna su contenido"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error leyendo {file_path}: {e}")
        return {}

def calculate_vulnerability_hash(vuln_name: str, vuln_type: str) -> str:
    """Calcula un hash único para identificar vulnerabilidades duplicadas"""
    # Normalizar nombres para mejor correlación
    normalized_name = re.sub(r'[^\w\s]', '', vuln_name.lower().strip())
    normalized_type = re.sub(r'[^\w\s]', '', vuln_type.lower().strip())
    
    hash_input = f"{normalized_name}_{normalized_type}"
    return hashlib.md5(hash_input.encode()).hexdigest()[:8]

def get_severity_priority(severity: str) -> int:
    """Retorna prioridad numérica para ordenar severidades"""
    severity_map = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1
    }
    return severity_map.get(severity.lower(), 0)

def assign_priority(severity: str, confidence: str, has_exploit: bool) -> str:
    """Asigna prioridad P0-P3 basada en severidad, confianza y explotabilidad"""
    sev_priority = get_severity_priority(severity)
    conf_high = confidence.upper() == 'HIGH'
    
    if sev_priority >= 4 and conf_high:  # Critical + High confidence
        return "P0"
    elif sev_priority >= 3 and (conf_high or has_exploit):  # High + (High confidence OR exploit)
        return "P1"
    elif sev_priority >= 2:  # Medium
        return "P2"
    else:  # Low
        return "P3"

def generate_mitigation_recommendations(vuln_type: str, vuln_name: str) -> List[str]:
    """Genera recomendaciones de mitigación basadas en el tipo de vulnerabilidad"""
    recommendations = []
    
    vuln_type_lower = vuln_type.lower()
    vuln_name_lower = vuln_name.lower()
    
    if 'sql injection' in vuln_type_lower or 'sql' in vuln_name_lower:
        recommendations.extend([
            "Implementar consultas parametrizadas (prepared statements)",
            "Validar y sanitizar todas las entradas de usuario",
            "Aplicar principio de menor privilegio en base de datos",
            "Implementar WAF con reglas anti-SQL injection"
        ])
    
    elif 'xss' in vuln_type_lower or 'cross-site scripting' in vuln_name_lower:
        recommendations.extend([
            "Escapar todas las salidas HTML",
            "Implementar Content Security Policy (CSP)",
            "Validar y sanitizar entradas de usuario",
            "Usar bibliotecas de templating seguras"
        ])
    
    elif 'ssrf' in vuln_type_lower or 'server-side request forgery' in vuln_name_lower:
        recommendations.extend([
            "Implementar whitelist de URLs permitidas",
            "Validar y filtrar URLs de entrada",
            "Usar proxy interno para requests externos",
            "Implementar timeouts y límites de tamaño"
        ])
    
    elif 'idor' in vuln_type_lower or 'direct object reference' in vuln_name_lower:
        recommendations.extend([
            "Implementar controles de autorización robustos",
            "Usar referencias indirectas a objetos",
            "Validar permisos en cada acceso a recursos",
            "Implementar logging de accesos"
        ])
    
    elif 'path traversal' in vuln_type_lower or 'file inclusion' in vuln_name_lower:
        recommendations.extend([
            "Validar y sanitizar nombres de archivo",
            "Usar rutas absolutas y canonicalizadas",
            "Implementar chroot jail o sandboxing",
            "Restringir acceso a directorios sensibles"
        ])
    
    else:
        recommendations.extend([
            "Revisar y actualizar código vulnerable",
            "Implementar validación de entrada robusta",
            "Aplicar principios de seguridad por diseño",
            "Realizar pruebas de seguridad regulares"
        ])
    
    return recommendations

class TriageAgent:
    """Agente especializado en triage inteligente de vulnerabilidades usando LLM"""
    
    def __init__(
        self,
        vulnerability_repository: VulnerabilityRepository,
        analysis_repository: AnalysisRepository,
        triage_result_repository: TriageResultRepository
    ):
        self.vulnerability_repository = vulnerability_repository
        self.analysis_repository = analysis_repository
        self.triage_result_repository = triage_result_repository
        
        # Configurar el agente CAI para correlación inteligente
        self.agent = Agent(
            name="Vulnerability Triage Agent",
            description="Agente especializado en triage y correlación inteligente de vulnerabilidades",
            instructions="""
            Eres un experto en ciberseguridad especializado en análisis y correlación de vulnerabilidades.
            
            Tu tarea es realizar un triage inteligente de vulnerabilidades de múltiples fuentes, identificando duplicados y consolidando información.
            
            PROCESO DE TRIAGE INTELIGENTE:
            
            1. **Lectura de Fuentes Múltiples:**
               - Lee vulnerabilidades de static_agent_results.json
               - Lee vulnerabilidades de dynamic_analysis_results.json  
            
            2. **Correlación Inteligente:**
               - Analiza semánticamente nombres, tipos y descripciones de vulnerabilidades
               - Identifica vulnerabilidades que son la MISMA vulnerabilidad reportada por diferentes fuentes
               - Considera variaciones en nomenclatura (ej: "SQL Injection" vs "Inyección SQL")
               - Evalúa similitud en ubicaciones, endpoints, parámetros afectados
               - Agrupa vulnerabilidades relacionadas o duplicadas
            
            3. **Consolidación de Evidencia:**
               - Combina evidencia de todas las fuentes para cada vulnerabilidad única
               - Mantén trazabilidad de qué fuente aportó cada evidencia
               - Prioriza evidencia de explotación exitosa (dynamic) sobre análisis estático
            
            4. **Determinación de Estado Final:**
               - Si cualquier fuente confirma que es "vulnerable", el estado final es "vulnerable"
               - Calcula confianza basada en número de fuentes que confirman la vulnerabilidad
               - Reclasifica severidad en base a la evidencia y el estado final
            
            5. **Asignación de Prioridad:**
               - P0: Critical con evidencia de explotación
               - P1: High con evidencia de explotación, o Critical sin explotación
               - P2: Medium con evidencia, o High sin explotación
               - P3: Low o vulnerabilidades sin evidencia clara
            
            6. **Generación de Recomendaciones:**
               - Proporciona recomendaciones específicas de mitigación
               - Considera el contexto de la aplicación y tipo de vulnerabilidad
            
            ESTRUCTURA DE SALIDA REQUERIDA:
            
            ```json
            {
              "triage_summary": {
                "total_vulnerabilities_before_deduplication": <número>,
                "total_unique_vulnerabilities": <número>,
                "vulnerabilities_by_severity": {
                  "Critical": <número>,
                  "High": <número>,
                  "Medium": <número>,
                  "Low": <número>
                },
                "analysis_timestamp": "<ISO timestamp>",
                "sources_processed": <número>,
                "source_files": ["Static Agent Results", "Dynamic Analysis Results", "Report Analysis"]
              },
              "consolidated_vulnerabilities": [
                {
                  "vulnerability_name": "<nombre consolidado>",
                  "vulnerability_type": "<tipo>",
                  "consolidated_severity": "<severidad más alta>",
                  "final_status": "vulnerable|not_vulnerable",
                  "priority": "P0|P1|P2|P3",
                  "description": "<descripción consolidada>",
                  "consolidated_evidence": [
                    "<evidencia de fuente 1>",
                    "<evidencia de fuente 2>",
                    "..."
                  ],
                  "sources": ["<fuente1>", "<fuente2>"],
                  "confidence": "HIGH|MEDIUM|LOW",
                  "mitigation_recommendations": [
                    "<recomendación 1>",
                    "<recomendación 2>",
                    "..."
                  ]
                }
              ]
            }
            ```
            
            IMPORTANTE:
            - Sé muy cuidadoso al identificar duplicados - analiza semánticamente el contenido
            - Una vulnerabilidad de "SQL Injection en formulario de login" es la MISMA si aparece en múltiples fuentes
            - Consolida toda la evidencia disponible para cada vulnerabilidad única
            - Mantén la precisión técnica y no inventes información
            """,
            tools=[
                read_json_file_tool,
                save_triage_results_tool,
            ],
            model=OpenAIChatCompletionsModel(
                model=os.getenv('CAI_MODEL', "gpt-5-nano"),
                openai_client=AsyncOpenAI(),
            )
        )
    
    async def perform_triage(
        self, 
        report_id: str,
        vulnerabilities: List[Vulnerability], 
        analyses: List[Analysis]
    ) -> TriageResult:
        """Realiza triage inteligente de vulnerabilidades y análisis"""
        
        # Preparar datos para el análisis
        vulnerabilities_data = []
        for vuln in vulnerabilities:
            vuln_data = {
                "id": vuln.id,
                "name": vuln.name,
                "type": vuln.vulnerability_type,
                "severity": vuln.severity.value,
                "description": vuln.description,
                "file_path": vuln.file_path,
                "line_number": vuln.line_number,
                "evidence": vuln.evidence,
                "status": vuln.status.value,
                "sources": vuln.sources
            }
            vulnerabilities_data.append(vuln_data)
        
        analyses_data = []
        for analysis in analyses:
            analysis_data = {
                "id": analysis.id,
                "vulnerability_id": analysis.vulnerability_id,
                "analysis_type": analysis.analysis_type.value,
                "status": analysis.status,
                "confidence": analysis.confidence.value,
                "evidence": analysis.evidence,
                "analysis_summary": analysis.analysis_summary,
                "file_path": analysis.file_path,
                "line_number": analysis.line_number
            }
            analyses_data.append(analysis_data)
        
        # Crear prompt para el agente
        prompt = f"""
        Realiza un triage inteligente de vulnerabilidades con los siguientes datos:
        
        **VULNERABILIDADES ({len(vulnerabilities_data)}):**
        {json.dumps(vulnerabilities_data, indent=2, ensure_ascii=False)}
        
        **ANÁLISIS ({len(analyses_data)}):**
        {json.dumps(analyses_data, indent=2, ensure_ascii=False)}
        
        INSTRUCCIONES ESPECÍFICAS:
        
        1. **Analiza y correlaciona** las vulnerabilidades:
           - Identifica vulnerabilidades duplicadas entre fuentes
           - Considera variaciones en nombres y tipos
           - Evalúa similitud en ubicaciones y parámetros afectados
        
        2. **Consolida la información**:
           - Combina evidencia de todas las fuentes
        
        3. **Realiza el triage**:
           - Determina estado final basado en análisis
           - Asigna prioridad basada en severidad y evidencia (real)
           - Reclasifica severidad en base a la evidencia y el estado final
        
        4. **Genera el reporte consolidado** con estructura JSON válida
        
        5. **Procesa los resultados** usando save_triage_results_tool para validar el formato
        
        Procede con el análisis completo.
        """
        
        print("🤖 Iniciando análisis inteligente con LLM...")
        result = await Runner.run(self.agent, prompt)
        
        print("✅ Análisis completado por el agente")
        print(result.final_output)
        
        # Procesar resultados directamente del output del agente
        try:
            # Buscar el JSON de resultados en el output del agente
            output_text = result.final_output
            results_data = None
            
            # Buscar el marcador de resultados JSON
            if "TRIAGE_RESULTS_JSON:" in output_text:
                json_start = output_text.find("TRIAGE_RESULTS_JSON:") + len("TRIAGE_RESULTS_JSON:")
                json_text = output_text[json_start:].strip()
                
                # Extraer solo el JSON válido
                try:
                    results_data = json.loads(json_text)
                except json.JSONDecodeError:
                    # Intentar extraer JSON usando regex si el parsing directo falla
                    import re
                    json_match = re.search(r'\{.*\}', json_text, re.DOTALL)
                    if json_match:
                        results_data = json.loads(json_match.group())
            
            if results_data:
                # Extraer información del triage
                triage_summary = results_data.get('triage_summary', {})
                consolidated_vulns = results_data.get('consolidated_vulnerabilities', [])
                
                # Calcular distribución de severidad
                severity_distribution = triage_summary.get('vulnerabilities_by_severity', {})
                
                # Crear entidad TriageResult
                triage_result = TriageResult(
                    id=str(uuid.uuid4()),
                    report_id=report_id,
                    analysis_ids=[a.id for a in analyses if a.id],
                    consolidated_vulnerability_ids=[v['vulnerability_name'] for v in consolidated_vulns],
                    vulnerabilities_by_severity=severity_distribution,
                    total_vulnerabilities_before_deduplication=triage_summary.get('total_vulnerabilities_before_deduplication', len(vulnerabilities)),
                    total_unique_vulnerabilities=triage_summary.get('total_unique_vulnerabilities', len(consolidated_vulns)),
                    sources_processed=triage_summary.get('sources_processed', 2),
                    source_files=triage_summary.get('source_files', ["Static Agent Results", "Dynamic Analysis Results"]),
                    triage_summary=triage_summary,  # Agregar el resumen completo
                    analysis_timestamp=datetime.utcnow(),
                    analysis_completed_at=datetime.utcnow()
                )
                
                # Guardar resultado en MongoDB
                await self.triage_result_repository.save(triage_result)
                
                print(f"✅ Resultados de triage guardados en MongoDB para reporte {report_id}")
                return triage_result
                
        except Exception as e:
            print(f"Error al procesar los resultados generados: {e}")
        
        # Crear resultado básico si falla el procesamiento
        basic_triage_summary = {
            "total_vulnerabilities_before_deduplication": len(vulnerabilities),
            "unique_vulnerabilities_after_deduplication": len(vulnerabilities),
            "sources_processed": ["Basic Triage"],
            "source_files_analyzed": 1,
            "analysis_completed_at": datetime.utcnow().isoformat()
        }
        
        basic_triage = TriageResult(
            id=str(uuid.uuid4()),
            report_id=report_id,
            analysis_ids=[a.id for a in analyses if a.id],
            consolidated_vulnerability_ids=[v.id for v in vulnerabilities],
            vulnerabilities_by_severity=self._calculate_basic_severity_distribution(vulnerabilities),
            total_vulnerabilities_before_deduplication=len(vulnerabilities),
            total_unique_vulnerabilities=len(vulnerabilities),
            sources_processed=1,
            source_files=["Basic Triage"],
            triage_summary=basic_triage_summary,
            analysis_timestamp=datetime.utcnow(),
            analysis_completed_at=datetime.utcnow()
        )
        
        await self.triage_result_repository.save(basic_triage)
        return basic_triage
    
    def _calculate_basic_severity_distribution(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Calcula distribución básica de severidad"""
        distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.severity.value.capitalize()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution

async def main():
    """Función principal para ejecutar el triage inteligente"""
    
    # Configurar el agente
    set_tracing_disabled(True)
    
    print("="*60)
    print("🔍 AGENTE DE TRIAGE INTELIGENTE DE VULNERABILIDADES")
    print("="*60)
    
    # Archivos de análisis a procesar
    analysis_files = [
        "static_agent_results.json",
        "dynamic_analysis_results.json"
    ]
    
    print(f"📁 Procesando {len(analysis_files)} archivos:")
    for file in analysis_files:
        print(f"  • {file}")
    
    print()
    
    # Crear instancia del agente de triage
    triage_agent = TriageAgent()
    
    # Realizar triage inteligente
    print("🔄 Iniciando triage inteligente con correlación semántica...")
    result = await triage_agent.perform_intelligent_triage(analysis_files)
    
    if "error" in result:
        print(f"❌ Error en el triage: {result['error']}")
        return
    
    # Mostrar resumen
    print("\n" + "="*60)
    print("📋 RESUMEN DEL TRIAGE INTELIGENTE:")
    print("="*60)
    
    summary = result.get('triage_summary', {})
    
    print(f"📈 Total vulnerabilidades antes de deduplicación: {summary.get('total_vulnerabilities_before_deduplication', 0)}")
    print(f"🎯 Vulnerabilidades únicas identificadas: {summary.get('total_unique_vulnerabilities', 0)}")
    print(f"📂 Fuentes procesadas: {summary.get('sources_processed', 0)}")
    
    severity_dist = summary.get('vulnerabilities_by_severity', {})
    print(f"\n🎚️  Distribución por severidad:")
    for severity, count in severity_dist.items():
        print(f"  • {severity}: {count}")
    
    timestamp = summary.get('analysis_timestamp', 'N/A')
    print(f"\n⏰ Análisis completado: {timestamp}")
    
    # Mostrar top vulnerabilidades
    vulns = result.get('consolidated_vulnerabilities', [])
    if vulns:
        print(f"\n🚨 Top 5 vulnerabilidades por prioridad:")
        sorted_vulns = sorted(vulns, key=lambda x: x.get('priority', 'P3'))
        for i, vuln in enumerate(sorted_vulns[:5], 1):
            priority = vuln.get('priority', 'P?')
            name = vuln.get('vulnerability_name', 'Unknown')
            severity = vuln.get('consolidated_severity', 'Unknown')
            print(f"  {i}. [{priority}] {name} ({severity})")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    asyncio.run(main())
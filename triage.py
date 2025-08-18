#!/usr/bin/env python3
"""
Triage Agent - Consolida y prioriza vulnerabilidades de múltiples fuentes de análisis

Este agente se encarga de:
- Leer vulnerabilidades desde múltiples archivos JSON (análisis estático, dinámico, etc.)
- Detectar y correlacionar vulnerabilidades duplicadas usando análisis semántico con LLM
- Consolidar evidencia de múltiples fuentes
- Asignar severidad y prioridad basada en evidencia consolidada
- Proporcionar recomendaciones de mitigación específicas
- Determinar estado final de vulnerabilidad (vulnerable/no vulnerable)
"""

import os
import sys
import json
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
import hashlib
import re

from cai.sdk.agents import Runner, Agent, OpenAIChatCompletionsModel, set_tracing_disabled
from openai import AsyncOpenAI
from cai.sdk.agents import function_tool

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
def save_triage_results_tool(results: str, output_file: str = 'triage_results.json') -> str:
    """Guarda los resultados del triage en un archivo JSON"""
    try:
        # Parsear el JSON string a dict
        results_dict = json.loads(results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results_dict, f, indent=2, ensure_ascii=False)
        
        return f"Resultados guardados exitosamente en {output_file}"
    except Exception as e:
        return f"Error guardando resultados: {e}"

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
    
    def __init__(self):
        self.vulnerabilities = {}
        self.sources_data = {}
        
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
               - Usa la severidad MÁS ALTA encontrada entre todas las fuentes
               - Calcula confianza basada en número de fuentes que confirman la vulnerabilidad
            
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
    
    async def perform_intelligent_triage(self, files: List[str]) -> Dict[str, Any]:
        """Realiza triage inteligente usando el agente CAI"""
        
        # Verificar que los archivos existen
        existing_files = []
        for file_path in files:
            if os.path.exists(file_path):
                existing_files.append(file_path)
                print(f"  ✓ Archivo encontrado: {file_path}")
            else:
                print(f"  ✗ Archivo no encontrado: {file_path}")
        
        if not existing_files:
            return {"error": "No se encontraron archivos de análisis"}
        
        # Crear prompt para el agente
        prompt = f"""
        Realiza un triage inteligente de vulnerabilidades de los siguientes archivos:
        
        Archivos a procesar:
        {chr(10).join(f"- {file}" for file in existing_files)}
        
        INSTRUCCIONES ESPECÍFICAS:
        
        1. **Lee cada archivo JSON** usando la herramienta read_json_file_tool
        
        2. **Analiza y correlaciona** las vulnerabilidades encontradas:
           - Identifica vulnerabilidades duplicadas entre fuentes
           - Considera variaciones en nombres (ej: "SQL Injection" = "Inyección SQL")
           - Evalúa similitud en ubicaciones y parámetros afectados
        
        3. **Consolida la información**:
           - Combina evidencia de todas las fuentes
           - Usa la severidad más alta encontrada
           - Determina estado final (vulnerable si cualquier fuente lo confirma)
           - Asigna prioridad basada en severidad y evidencia de explotación
        
        4. **Genera el reporte consolidado** con la estructura JSON especificada
        
        5. **Guarda los resultados** usando save_triage_results_tool
        
        Procede con el análisis completo.
        """
        
        print("🤖 Iniciando análisis inteligente con LLM...")
        result = await Runner.run(self.agent, prompt)
        
        print("✅ Análisis completado por el agente")
        print(result.final_output)
        
        # Intentar cargar el JSON de resultados generado
        try:
            results_file = "triage_results.json"
            if os.path.exists(results_file):
                with open(results_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error al cargar los resultados generados: {e}")
        
        return {"error": "No se pudieron generar los resultados de triage"}

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
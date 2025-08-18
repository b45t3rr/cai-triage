#!/usr/bin/env python3
"""
Report Reader Agent - Extrae texto de PDFs y serializa información de vulnerabilidades en JSON

Este agente se encarga de:
- Extraer texto de archivos PDF
- Interpretar el contenido del reporte de seguridad
- Serializar la información en formato JSON estructurado
- Identificar scope, credenciales, vulnerabilidades con severidad y detalles
"""

import os
import sys
import json
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path

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


@function_tool
def save_json_report(json_data: str, output_path: str = "report_analysis.json") -> str:
    """Guarda el reporte JSON en un archivo"""
    try:
        # Validar que sea JSON válido
        parsed_data = json.loads(json_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, indent=2, ensure_ascii=False)
        
        return f"Reporte JSON guardado exitosamente en: {output_path}"
    except json.JSONDecodeError as e:
        return f"Error: JSON inválido - {str(e)}"
    except Exception as e:
        return f"Error al guardar archivo: {str(e)}"


class ReportReaderAgent:
    """Agente especializado en leer reportes de seguridad y extraer información estructurada"""
    
    def __init__(self):
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
            - Estructura toda la información en un JSON válido y bien formateado
            - No inventes información que no esté en el texto
            - Si alguna sección no está presente, marca como "No especificado"
            - Mantén la precisión técnica de los términos de seguridad
            - Organiza las vulnerabilidades por severidad (de mayor a menor)
            """,
            tools=[
                extract_pdf_text,
                save_json_report,
            ],
            model=OpenAIChatCompletionsModel(
                model=os.getenv('CAI_MODEL', "gpt-5-nano"),
                openai_client=AsyncOpenAI(),
            )
        )
    
    async def process_pdf_report(self, pdf_path: str, output_json_path: Optional[str] = None) -> Dict[str, Any]:
        """Procesa un reporte PDF y retorna la información estructurada"""
        
        if output_json_path is None:
            pdf_name = Path(pdf_path).stem
            output_json_path = f"{pdf_name}_analysis.json"
        
        prompt = f"""
        Analiza el siguiente reporte de seguridad PDF y extrae toda la información relevante:
        
        1. Primero, extrae el texto del archivo PDF: {pdf_path}
        2. Analiza el contenido y estructura la información en formato JSON
        3. Guarda el resultado en: {output_json_path}
        
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
        
        # Intentar cargar el JSON generado
        try:
            if os.path.exists(output_json_path):
                with open(output_json_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error al cargar el JSON generado: {e}")
        
        return {"error": "No se pudo generar el análisis JSON"}


async def main():
    """Función principal para probar el agente"""
    # Configurar el agente
    set_tracing_disabled(True)
    
    # Crear instancia del agente
    reader_agent = ReportReaderAgent()
    
    # Ruta del PDF de ejemplo (ajustar según sea necesario)
    pdf_path = "testing-assets/report.pdf"
    
    if not os.path.exists(pdf_path):
        print(f"Archivo PDF no encontrado: {pdf_path}")
        print("Por favor, proporciona la ruta correcta al archivo PDF.")
        return
    
    print(f"Procesando reporte: {pdf_path}")
    
    # Procesar el reporte
    result = await reader_agent.process_pdf_report(pdf_path)
    
    print("\n" + "="*50)
    print("RESULTADO DEL ANÁLISIS:")
    print("="*50)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
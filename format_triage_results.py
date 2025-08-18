#!/usr/bin/env python3
"""
Script para formatear y mostrar los resultados de triage de forma bonita en la CLI.
Uso: python format_triage_results.py <archivo_json>
"""

import json
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich.progress import Progress, BarColumn, TextColumn
from rich.columns import Columns
from rich.align import Align
from rich import box


class TriageResultsFormatter:
    """Formateador para resultados de triage"""
    
    def __init__(self):
        self.console = Console()
        self.severity_colors = {
            "Critical": "red",
            "High": "orange3",
            "Medium": "yellow",
            "Low": "green",
            "Info": "blue"
        }
        self.priority_colors = {
            "P0": "red",
            "P1": "orange3",
            "P2": "yellow",
            "P3": "green"
        }
        self.confidence_colors = {
            "HIGH": "green",
            "MEDIUM": "yellow",
            "LOW": "red"
        }
        self.status_colors = {
            "vulnerable": "red",
            "not_vulnerable": "green",
            "unknown": "yellow"
        }
    
    def load_json_file(self, file_path: str) -> Dict[str, Any]:
        """Carga el archivo JSON de resultados de triage"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.console.print(f"[red]Error: No se encontró el archivo {file_path}[/red]")
            sys.exit(1)
        except json.JSONDecodeError as e:
            self.console.print(f"[red]Error: El archivo no contiene JSON válido: {e}[/red]")
            sys.exit(1)
    
    def format_timestamp(self, timestamp_str: str) -> str:
        """Formatea un timestamp ISO a formato legible"""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return timestamp_str
    
    def create_summary_panel(self, triage_summary: Dict[str, Any]) -> Panel:
        """Crea un panel con el resumen del triage"""
        # Crear tabla de estadísticas
        stats_table = Table(show_header=False, box=box.SIMPLE)
        stats_table.add_column("Métrica", style="bold cyan")
        stats_table.add_column("Valor", justify="right")
        
        stats_table.add_row("Total vulnerabilidades (antes dedup)", str(triage_summary.get('total_vulnerabilities_before_deduplication', 0)))
        stats_table.add_row("Vulnerabilidades únicas", str(triage_summary.get('total_unique_vulnerabilities', 0)))
        stats_table.add_row("Fuentes procesadas", str(triage_summary.get('sources_processed', 0)))
        
        if 'analysis_timestamp' in triage_summary:
            stats_table.add_row("Timestamp análisis", self.format_timestamp(triage_summary['analysis_timestamp']))
        
        # Crear gráfico de barras para severidades
        severity_dist = triage_summary.get('vulnerabilities_by_severity', {})
        severity_bars = []
        
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = severity_dist.get(severity, 0)
            if count > 0:
                color = self.severity_colors.get(severity, "white")
                bar = f"[{color}]{'█' * min(count * 2, 20)} {count}[/{color}]"
                severity_bars.append(f"{severity:8}: {bar}")
        
        severity_text = "\n".join(severity_bars) if severity_bars else "No hay vulnerabilidades"
        
        # Fuentes procesadas
        sources = triage_summary.get('source_files', [])
        sources_text = "\n".join([f"• {source}" for source in sources]) if sources else "No especificadas"
        
        content = f"""
{stats_table}

[bold yellow]Distribución por Severidad:[/bold yellow]
{severity_text}

[bold cyan]Fuentes Procesadas:[/bold cyan]
{sources_text}
        """.strip()
        
        return Panel(
            content,
            title="📊 Resumen del Triage",
            border_style="blue",
            padding=(1, 2)
        )
    
    def create_vulnerability_panel(self, vuln: Dict[str, Any], index: int) -> Panel:
        """Crea un panel para una vulnerabilidad individual"""
        name = vuln.get('vulnerability_name', 'Sin nombre')
        vuln_type = vuln.get('vulnerability_type', 'Sin tipo')
        severity = vuln.get('consolidated_severity', 'Unknown')
        status = vuln.get('final_status', 'unknown')
        priority = vuln.get('priority', 'P3')
        confidence = vuln.get('confidence', 'LOW')
        description = vuln.get('description', 'Sin descripción')
        
        # Colores según severidad y estado
        severity_color = self.severity_colors.get(severity, "white")
        status_color = self.status_colors.get(status, "white")
        priority_color = self.priority_colors.get(priority, "white")
        confidence_color = self.confidence_colors.get(confidence, "white")
        
        # Header con información clave
        header = f"[bold]{name}[/bold] ([{severity_color}]{severity}[/{severity_color}])"
        
        # Crear tabla de detalles
        details_table = Table(show_header=False, box=None, padding=(0, 1))
        details_table.add_column("Campo", style="bold cyan", width=12)
        details_table.add_column("Valor")
        
        details_table.add_row("Tipo:", vuln_type)
        details_table.add_row("Estado:", f"[{status_color}]{status.upper()}[/{status_color}]")
        details_table.add_row("Prioridad:", f"[{priority_color}]{priority}[/{priority_color}]")
        details_table.add_row("Confianza:", f"[{confidence_color}]{confidence}[/{confidence_color}]")
        
        # Fuentes
        sources = vuln.get('sources', [])
        sources_text = ", ".join(sources) if sources else "No especificadas"
        details_table.add_row("Fuentes:", sources_text)
        
        content_parts = [str(details_table)]
        
        # Descripción
        if description and description != 'Sin descripción':
            content_parts.append(f"\n[bold yellow]Descripción:[/bold yellow]\n{description}")
        
        # Evidencia
        evidence = vuln.get('consolidated_evidence', [])
        if evidence:
            content_parts.append("\n[bold red]Evidencia:[/bold red]")
            for i, ev in enumerate(evidence[:3], 1):  # Mostrar máximo 3 evidencias
                content_parts.append(f"  {i}. {ev}")
            if len(evidence) > 3:
                content_parts.append(f"  ... y {len(evidence) - 3} más")
        
        # Recomendaciones de mitigación
        mitigations = vuln.get('mitigation_recommendations', [])
        if mitigations:
            content_parts.append("\n[bold green]Recomendaciones:[/bold green]")
            for i, rec in enumerate(mitigations[:3], 1):  # Mostrar máximo 3 recomendaciones
                content_parts.append(f"  • {rec}")
            if len(mitigations) > 3:
                content_parts.append(f"  ... y {len(mitigations) - 3} más")
        
        content = "\n".join(content_parts)
        
        # Determinar el estilo del borde según la severidad
        border_style = severity_color
        
        return Panel(
            content,
            title=f"🔍 Vulnerabilidad #{index + 1}: {header}",
            border_style=border_style,
            padding=(1, 2)
        )
    
    def display_results(self, data: Dict[str, Any]):
        """Muestra los resultados formateados"""
        self.console.clear()
        
        # Título principal
        title = Text("RESULTADOS DEL TRIAGE DE SEGURIDAD", style="bold magenta")
        self.console.print(Align.center(title))
        self.console.print("\n")
        
        # Resumen
        triage_summary = data.get('triage_summary', {})
        summary_panel = self.create_summary_panel(triage_summary)
        self.console.print(summary_panel)
        self.console.print("\n")
        
        # Vulnerabilidades consolidadas
        vulnerabilities = data.get('consolidated_vulnerabilities', [])
        
        if not vulnerabilities:
            no_vulns_panel = Panel(
                "[green]¡Excelente! No se encontraron vulnerabilidades.[/green]",
                title="✅ Estado de Seguridad",
                border_style="green"
            )
            self.console.print(no_vulns_panel)
            return
        
        # Mostrar cada vulnerabilidad
        self.console.print(f"[bold cyan]📋 Vulnerabilidades Encontradas ({len(vulnerabilities)}):[/bold cyan]\n")
        
        for i, vuln in enumerate(vulnerabilities):
            vuln_panel = self.create_vulnerability_panel(vuln, i)
            self.console.print(vuln_panel)
            if i < len(vulnerabilities) - 1:  # No agregar espacio después de la última
                self.console.print("")
        
        # Estadísticas finales
        self.console.print("\n")
        stats_text = f"[bold]Análisis completado:[/bold] {len(vulnerabilities)} vulnerabilidades únicas identificadas"
        final_panel = Panel(
            Align.center(stats_text),
            border_style="blue"
        )
        self.console.print(final_panel)


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Formatea y muestra resultados de triage de seguridad",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python format_triage_results.py triage_result.json
  python format_triage_results.py /path/to/results.json
        """
    )
    parser.add_argument(
        'json_file',
        help='Archivo JSON con los resultados del triage'
    )
    parser.add_argument(
        '--no-clear',
        action='store_true',
        help='No limpiar la pantalla antes de mostrar los resultados'
    )
    
    args = parser.parse_args()
    
    formatter = TriageResultsFormatter()
    
    # Cargar y mostrar los resultados
    try:
        data = formatter.load_json_file(args.json_file)
        
        if not args.no_clear:
            formatter.console.clear()
        
        formatter.display_results(data)
        
    except KeyboardInterrupt:
        formatter.console.print("\n[yellow]Operación cancelada por el usuario[/yellow]")
        sys.exit(0)
    except Exception as e:
        formatter.console.print(f"[red]Error inesperado: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
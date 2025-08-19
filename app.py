#!/usr/bin/env python3
"""
Aplicación principal para análisis de vulnerabilidades

Esta aplicación orquesta el flujo completo de análisis de vulnerabilidades:
report_reader -> static_agent -> dynamic_agent -> triage

Uso:
    python app.py --pdf report.pdf --source path/to/source --url http://localhost --model openai:gpt-5-nano
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Optional

# Agregar el directorio src al path para importar módulos
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.infrastructure.database import DatabaseManager, get_database
from src.infrastructure.mongodb_repositories import (
    MongoDBReportRepository,
    MongoDBVulnerabilityRepository,
    MongoDBAnalysisRepository,
    MongoDBTriageResultRepository
)
from src.application.services import (
    ReportProcessingService,
    StaticAnalysisService,
    DynamicAnalysisService,
    TriageService,
    VulnerabilityAnalysisOrchestrator
)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('vulnerability_analysis.log')
    ]
)

logger = logging.getLogger(__name__)


def setup_environment():
    """Configura las variables de entorno necesarias"""
    # Cargar variables de entorno desde .env si existe
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ.setdefault(key.strip(), value.strip())
    
    # Configurar valores por defecto
    os.environ.setdefault("MONGODB_CONNECTION_STRING", "mongodb://triage_user:triage_password@localhost:27017/vulnerability_triage")
    os.environ.setdefault("MONGODB_DATABASE_NAME", "vulnerability_triage")
    os.environ.setdefault("OPENAI_API_KEY", "")
    os.environ.setdefault("OPENAI_MODEL", "gpt-5-nano")
    os.environ.setdefault("SEMGREP_TIMEOUT", "300")
    os.environ.setdefault("SEMGREP_MEMORY_LIMIT", "2048")
    os.environ.setdefault("DYNAMIC_ANALYSIS_TIMEOUT", "600")
    os.environ.setdefault("LOG_LEVEL", "INFO")


def validate_arguments(args) -> bool:
    """Valida los argumentos de línea de comandos"""
    errors = []
    
    # Validar archivo PDF
    if not Path(args.pdf).exists():
        errors.append(f"PDF file not found: {args.pdf}")
    elif not args.pdf.lower().endswith('.pdf'):
        errors.append(f"File must be a PDF: {args.pdf}")
    
    # Validar directorio de código fuente
    if not Path(args.source).exists():
        errors.append(f"Source directory not found: {args.source}")
    elif not Path(args.source).is_dir():
        errors.append(f"Source path must be a directory: {args.source}")
    
    # Validar URL
    if not args.url.startswith(('http://', 'https://')):
        errors.append(f"URL must start with http:// or https://: {args.url}")
    
    # Validar modelo
    valid_models = [
        "openai:gpt-5-nano", "openai:gpt-5-nano-turbo", "openai:gpt-3.5-turbo",
        "anthropic:claude-3-opus", "anthropic:claude-3-sonnet", "anthropic:claude-3-haiku"
    ]
    if args.model not in valid_models:
        logger.warning(f"Model {args.model} not in validated list: {valid_models}")
    
    # Validar API key si es necesario
    if args.model.startswith("openai:") and not os.getenv("OPENAI_API_KEY"):
        errors.append("OPENAI_API_KEY environment variable is required for OpenAI models")
    elif args.model.startswith("anthropic:") and not os.getenv("ANTHROPIC_API_KEY"):
        errors.append("ANTHROPIC_API_KEY environment variable is required for Anthropic models")
    
    if errors:
        for error in errors:
            logger.error(error)
        return False
    
    return True


def setup_repositories(database):
    """Configura los repositorios"""
    return {
        'report_repo': MongoDBReportRepository(database),
        'vulnerability_repo': MongoDBVulnerabilityRepository(database),
        'analysis_repo': MongoDBAnalysisRepository(database),
        'triage_repo': MongoDBTriageResultRepository(database)
    }


def setup_services(repositories):
    """Configura los servicios de aplicación"""
    report_service = ReportProcessingService(
        repositories['report_repo'],
        repositories['vulnerability_repo']
    )
    
    static_service = StaticAnalysisService(
        repositories['analysis_repo'],
        repositories['vulnerability_repo']
    )
    
    dynamic_service = DynamicAnalysisService(
        repositories['analysis_repo'],
        repositories['vulnerability_repo']
    )
    
    triage_service = TriageService(
        repositories['triage_repo'],
        repositories['vulnerability_repo'],
        repositories['analysis_repo']
    )
    
    orchestrator = VulnerabilityAnalysisOrchestrator(
        report_service,
        static_service,
        dynamic_service,
        triage_service
    )
    
    return orchestrator


def print_results_summary(triage_result):
    """Imprime un resumen de los resultados"""
    print("\n" + "="*80)
    print("VULNERABILITY ANALYSIS RESULTS SUMMARY")
    print("="*80)
    
    print(f"\nReport ID: {triage_result.report_id}")
    print(f"Triage ID: {triage_result.id}")
    print(f"Analysis completed at: {triage_result.analysis_completed_at}")
    
    print("\nTriage Summary:")
    summary = triage_result.triage_summary
    print(f"  • Total vulnerabilities (before deduplication): {summary.get('total_vulnerabilities_before_deduplication', 0)}")
    print(f"  • Unique vulnerabilities (after deduplication): {summary.get('unique_vulnerabilities_after_deduplication', 0)}")
    print(f"  • Sources processed: {', '.join(summary.get('sources_processed', []))}")
    print(f"  • Analysis files processed: {summary.get('source_files_analyzed', 0)}")
    
    print("\nSeverity Distribution:")
    for severity, count in triage_result.vulnerabilities_by_severity.items():
        if count > 0:
            print(f"  • {severity}: {count}")
    
    print(f"\nConsolidated Vulnerabilities: {len(triage_result.consolidated_vulnerability_ids)}")
    
    print("\n" + "="*80)
    print("Analysis completed successfully!")
    print("Results have been stored in MongoDB.")
    print("="*80)


async def main():
    """Función principal"""
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(
        description="Vulnerability Analysis Tool - Automated security assessment using AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app.py --pdf report.pdf --source ./src --url http://localhost:5000
  python app.py --pdf vuln_report.pdf --source /path/to/code --url https://app.example.com --model openai:gpt-5-nano-turbo
  python app.py --pdf report.pdf --source ./app --url http://localhost:3000 --model anthropic:claude-3-sonnet --verbose

Environment Variables:
  MONGODB_CONNECTION_STRING  MongoDB connection string (default: mongodb://localhost:27017)
  MONGODB_DATABASE_NAME      Database name (default: vulnerability_triage)
  OPENAI_API_KEY            OpenAI API key (required for OpenAI models)
  ANTHROPIC_API_KEY         Anthropic API key (required for Anthropic models)
  SEMGREP_TIMEOUT           Semgrep timeout in seconds (default: 300)
  DYNAMIC_ANALYSIS_TIMEOUT  Dynamic analysis timeout in seconds (default: 600)
        """
    )
    
    parser.add_argument(
        "--pdf",
        required=True,
        help="Path to the vulnerability report PDF file"
    )
    
    parser.add_argument(
        "--source",
        required=True,
        help="Path to the source code directory for static analysis"
    )
    
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL for dynamic analysis (e.g., http://localhost:5000)"
    )
    
    parser.add_argument(
        "--model",
        default="openai:gpt-5-nano",
        help="AI model to use (default: openai:gpt-5-nano). Options: openai:gpt-5-nano, openai:gpt-5-nano-turbo, openai:gpt-3.5-turbo, anthropic:claude-3-opus, anthropic:claude-3-sonnet, anthropic:claude-3-haiku"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--skip-static",
        action="store_true",
        help="Skip static analysis (useful for testing)"
    )
    
    parser.add_argument(
        "--skip-dynamic",
        action="store_true",
        help="Skip dynamic analysis (useful for testing)"
    )
    
    parser.add_argument(
        "--db-reset",
        action="store_true",
        help="Reset database before analysis (WARNING: deletes all data)"
    )
    
    args = parser.parse_args()
    
    # Configurar logging detallado si se solicita
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Verbose logging enabled")
    
    # Configurar entorno
    setup_environment()
    
    # Validar argumentos
    if not validate_arguments(args):
        sys.exit(1)
    
    # Convertir rutas a absolutas
    pdf_path = str(Path(args.pdf).resolve())
    source_path = str(Path(args.source).resolve())
    
    logger.info(f"Starting vulnerability analysis")
    logger.info(f"PDF Report: {pdf_path}")
    logger.info(f"Source Code: {source_path}")
    logger.info(f"Target URL: {args.url}")
    logger.info(f"AI Model: {args.model}")
    
    db_manager = None
    try:
        # Conectar a MongoDB
        logger.info("Connecting to MongoDB...")
        db_manager = DatabaseManager()
        database = db_manager.connect()
        
        # Resetear base de datos si se solicita
        if args.db_reset:
            logger.warning("Resetting database...")
            db_manager.drop_database()
            database = db_manager.connect()
        
        # Crear colecciones e índices
        db_manager.create_collections_and_indexes()
        
        # Configurar repositorios y servicios
        repositories = setup_repositories(database)
        orchestrator = setup_services(repositories)
        
        # Ejecutar análisis completo
        logger.info("Starting complete vulnerability analysis workflow...")
        
        if args.skip_static and args.skip_dynamic:
            logger.error("Cannot skip both static and dynamic analysis")
            sys.exit(1)
        
        # Por ahora ejecutamos el flujo completo
        # TODO: Implementar opciones para saltar pasos específicos
        triage_result = await orchestrator.run_complete_analysis(
            pdf_path=pdf_path,
            source_path=source_path,
            target_url=args.url,
            model=args.model
        )
        
        # Mostrar resumen de resultados
        print_results_summary(triage_result)
        
        # Mostrar estadísticas de la base de datos
        if args.verbose:
            stats = db_manager.get_database_stats()
            logger.info(f"Database statistics: {stats}")
        
        logger.info("Vulnerability analysis completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
        sys.exit(1)
    finally:
        # Cerrar conexión a la base de datos
        if db_manager:
            db_manager.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
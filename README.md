# 🛡️ Vulnerability AI Triage System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-green.svg)
![Clean Architecture](https://img.shields.io/badge/Architecture-Clean-orange.svg)
![License](https://img.shields.io/badge/License-Educational-red.svg)

*Un sistema avanzado de análisis de vulnerabilidades que combina IA, análisis estático y dinámico para el triage inteligente de reportes de seguridad*

</div>

*Un sistema de análisis de vulnerabilidades basado en agentes de IA que utiliza Clean Architecture y MongoDB para validar vulnerabilidades mediante análisis estático y dinámico.*

## Reporte

**Un reporte con información de resultados y configuración se encuentra [AQUI](https://github.com/b45t3rr/cai-triage/blob/main/docs/report.md)

## 🏗️ Arquitectura

El sistema sigue los principios de Clean Architecture con separación clara de responsabilidades:

```
src/
├── domain/                    # Entidades de negocio y reglas
│   ├── entities.py           # Modelos de dominio (Report, Vulnerability, Analysis, etc.)
│   ├── repositories.py       # Interfaces de repositorios
│   └── services.py           # Servicios de dominio
├── infrastructure/           # Implementaciones técnicas
│   ├── agents/              # Agentes de IA especializados
│   │   ├── report_reader.py # Extracción de vulnerabilidades de PDFs
│   │   ├── static_agent.py  # Análisis estático de código
│   │   ├── dynamic_agent.py # Validación dinámica
│   │   └── triage.py        # Consolidación y priorización
│   ├── database.py          # Configuración de MongoDB
│   └── mongodb_repositories.py # Implementaciones de repositorios
└── application/             # Casos de uso y orquestación
    └── services/           # Servicios de aplicación
        ├── report_processing_service.py
        ├── static_analysis_service.py
        ├── dynamic_analysis_service.py
        ├── triage_service.py
        └── vulnerability_analysis_orchestrator.py
```

## 🔄 Flujo de Agentes

El sistema orquesta 4 agentes especializados:

1. **Report Reader** → Extrae vulnerabilidades de reportes PDF
2. **Static Agent** → Análisis estático del código fuente
3. **Dynamic Agent** → Validación dinámica de vulnerabilidades
4. **Triage** → Consolidación y priorización de resultados

## 🚀 Instalación

### Prerrequisitos

- Python 3.9+
- Docker y Docker Compose
- Claves API de OpenAI (requerido)

### Instalación

### Instalación Manual

1. **Clonar el repositorio:**
```bash
git clone <repository-url>
cd triage-6
```

2. **Crear entorno virtual:**
```bash
python3 -m venv venv
source venv/bin/activate  # En Linux/Mac
# venv\Scripts\activate  # En Windows
```

3. **Instalar dependencias:**
```bash
pip install -r requirements.txt
```

4. **Configurar variables de entorno:**
```bash
cp .env.example .env
# Editar .env con tus claves API (OPENAI_API_KEY es requerido)
```

5. **Levantar MongoDB:**
```bash
docker-compose up -d
```

6. **Verificar la instalación:**
```bash
# MongoDB: localhost:27017
# Mongo Express: http://localhost:8081 (admin/admin123)
# Base de datos: vulnerability_triage
```

## 📖 Uso

### Comando Básico

```bash
python app.py --pdf report.pdf --source path/to/source --url http://localhost:5000 --model openai:gpt-4
```

### Parámetros

| Parámetro | Descripción | Requerido | Ejemplo |
|-----------|-------------|-----------|----------|
| `--pdf` | Ruta al reporte PDF | ✅ | `report.pdf` |
| `--source` | Directorio del código fuente | ❌ | `./src` |
| `--url` | URL objetivo para análisis dinámico | ❌ | `http://localhost:5000` |
| `--model` | Modelo de IA a utilizar | ✅ | `openai:gpt-4` |
| `--skip-static` | Omitir análisis estático | ❌ | `--skip-static` |
| `--skip-dynamic` | Omitir análisis dinámico | ❌ | `--skip-dynamic` |
| `--reset-db` | Reiniciar base de datos | ❌ | `--reset-db` |
| `--verbose` | Logging detallado | ❌ | `--verbose` |

### Modos de Operación

#### Análisis Completo
```bash
python app.py --pdf report.pdf --source ./src --url http://localhost:5000 --model openai:gpt-4
```

#### Solo Procesamiento de PDF
```bash
python app.py --pdf report.pdf --model openai:gpt-4 --skip-static --skip-dynamic
```

#### Solo Análisis Estático
```bash
python app.py --pdf report.pdf --source ./src --model openai:gpt-4 --skip-dynamic
```

#### Solo Análisis Dinámico
```bash
python app.py --pdf report.pdf --url http://localhost:5000 --model openai:gpt-4 --skip-static
```

### Ejemplos de Uso

**Análisis completo:**
```bash
python app.py \
  --pdf vulnerability_report.pdf \
  --source ./webapp/src \
  --url https://target-app.com \
  --model openai:gpt-4
```

**Con reinicio de BD:**
```bash
python app.py \
  --pdf report.pdf \
  --source ./code \
  --url http://localhost:3000 \
  --model anthropic:claude-3-sonnet \
  --reset-db
```

**Modo verbose:**
```bash
python app.py \
  --pdf pentest_report.pdf \
  --source ./application \
  --url http://192.168.1.100 \
  --model openai:gpt-4 \
  --verbose
```

## 🔧 Configuración

### Variables de Entorno Principales

```env
# MongoDB
MONGODB_CONNECTION_STRING=mongodb://triage_user:triage_password@localhost:27017/vulnerability_triage
MONGODB_DATABASE_NAME=vulnerability_triage

# OpenAI
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4

# Anthropic
ANTHROPIC_API_KEY=your_anthropic_api_key_here
ANTHROPIC_MODEL=claude-3-sonnet-20240229

# Análisis
DYNAMIC_ANALYSIS_TIMEOUT=600
STATIC_ANALYSIS_EXCLUDE_PATHS=node_modules,venv,.git
```

### Modelos Soportados

- **OpenAI:** `openai:gpt-4`, `openai:gpt-3.5-turbo`
- **Anthropic:** `anthropic:claude-3-sonnet`, `anthropic:claude-3-haiku`
- **Otros:** Configurables via variables de entorno

## 📊 Resultados

Los resultados se almacenan en MongoDB con las siguientes colecciones:

- **reports** - Metadatos de reportes procesados
- **vulnerabilities** - Vulnerabilidades identificadas
- **analyses** - Resultados de análisis estático/dinámico
- **triage_results** - Consolidación final y priorización

### Acceso a Resultados

**Via Mongo Express:**
- URL: http://localhost:8081
- Usuario: `admin`
- Contraseña: `admin123`

**Via MongoDB CLI:**
```bash
docker exec -it vulnerability_triage_mongodb mongosh -u triage_user -p triage_password vulnerability_triage
```

## 🏛️ Arquitectura Técnica

### Principios de Diseño

- **Clean Architecture** - Separación de capas y dependencias
- **SOLID** - Principios de diseño orientado a objetos
- **Repository Pattern** - Abstracción de acceso a datos
- **Dependency Injection** - Inversión de dependencias
- **Domain-Driven Design** - Modelado basado en dominio

### Capas del Sistema

1. **Domain Layer** (`src/domain/`)
   - Entidades de negocio
   - Reglas de dominio
   - Interfaces de repositorios

2. **Infrastructure Layer** (`src/infrastructure/`)
   - Implementaciones de repositorios
   - Configuración de base de datos
   - Integraciones externas

3. **Application Layer** (`src/application/`)
   - Casos de uso
   - Orquestación de servicios
   - Lógica de aplicación

4. **Presentation Layer** (`app.py`)
   - CLI interface
   - Configuración de entrada
   - Manejo de argumentos

### Flujo de Datos

```mermaid
graph TD
    A[PDF Report] --> B[Report Reader Agent]
    B --> C[MongoDB: Reports & Vulnerabilities]
    C --> D[Static Analysis Agent]
    D --> E[MongoDB: Analysis Results]
    E --> F[Dynamic Analysis Agent]
    F --> G[MongoDB: Validation Results]
    G --> H[Triage Agent]
    H --> I[MongoDB: Final Results]
```

## 🔍 Monitoreo y Debugging

### Logs

```bash
# Ver logs en tiempo real
tail -f vulnerability_analysis.log

# Logs con nivel DEBUG
LOG_LEVEL=DEBUG python app.py ...
```

### Métricas

- Puerto de métricas: `9090` (configurable)
- Tracing habilitado por defecto
- Monitoreo de performance incluido

### Troubleshooting

**Error de conexión a MongoDB:**
```bash
# Verificar que MongoDB esté corriendo
docker-compose ps

# Reiniciar servicios
docker-compose restart
```

**Error de API Keys:**
```bash
# Verificar configuración
grep -E "(OPENAI|ANTHROPIC)_API_KEY" .env

# Probar conexión
python -c "import openai; print('OpenAI OK')"
```

**Problemas de memoria:**
```bash
# Reducir concurrencia
export MAX_CONCURRENT_ANALYSES=2

# Limpiar cache
rm -rf __pycache__ .cache
```

**Base de datos corrupta:**
```bash
# Reiniciar completamente
docker-compose down -v
docker-compose up -d
```

## 🤝 Contribución

### Desarrollo Local

1. **Fork del repositorio**
2. **Crear rama de feature:**
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
3. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Ejecutar tests:**
   ```bash
   pytest tests/
   ```
5. **Commit y push:**
   ```bash
   git commit -m "feat: nueva funcionalidad"
   git push origin feature/nueva-funcionalidad
   ```

### Estándares de Código

- **Formato:** Black + isort
- **Linting:** flake8 + mypy
- **Tests:** pytest con >80% cobertura
- **Commits:** Conventional Commits

### Estructura de Tests

*Nota: La estructura de tests está en desarrollo. Contribuciones bienvenidas.*

## 📄 Licencia

Este proyecto es de uso educativo y de investigación en ciberseguridad.

## 🙏 Agradecimientos

- **OpenAI** por GPT-4 y la API
- **Anthropic** por Claude
- **MongoDB** por la base de datos
- **Comunidad Open Source** por las librerías utilizadas

---

**Desarrollado como parte de un desafio**

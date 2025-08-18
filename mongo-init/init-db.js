// Inicialización de la base de datos MongoDB para Vulnerability Triage

// Cambiar a la base de datos de vulnerability_triage
db = db.getSiblingDB('vulnerability_triage');

// Crear usuario para la aplicación
db.createUser({
  user: 'triage_user',
  pwd: 'triage_password',
  roles: [
    {
      role: 'readWrite',
      db: 'vulnerability_triage'
    }
  ]
});

// Crear colecciones con validación de esquema
db.createCollection('reports', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['title', 'file_path', 'created_at'],
      properties: {
        title: {
          bsonType: 'string',
          description: 'Report title is required and must be a string'
        },
        file_path: {
          bsonType: 'string',
          description: 'File path is required and must be a string'
        },
        client: {
          bsonType: 'string',
          description: 'Client name must be a string'
        },
        consultant: {
          bsonType: 'string',
          description: 'Consultant name must be a string'
        },
        version: {
          bsonType: 'string',
          description: 'Version must be a string'
        },
        scope_details: {
          bsonType: 'object',
          description: 'Scope details must be an object'
        },
        credentials: {
          bsonType: 'object',
          description: 'Credentials must be an object'
        },
        methodology: {
          bsonType: 'object',
          description: 'Methodology must be an object'
        },
        executive_summary: {
          bsonType: 'object',
          description: 'Executive summary must be an object'
        },
        created_at: {
          bsonType: 'date',
          description: 'Created at is required and must be a date'
        },
        report_date: {
          bsonType: 'date',
          description: 'Report date must be a date'
        },
        processed_at: {
          bsonType: 'date',
          description: 'Processed at must be a date'
        }
      }
    }
  }
});

db.createCollection('vulnerabilities', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['name', 'vulnerability_type', 'severity', 'status', 'confidence', 'priority', 'created_at'],
      properties: {
        name: {
          bsonType: 'string',
          description: 'Vulnerability name is required and must be a string'
        },
        vulnerability_type: {
          bsonType: 'string',
          description: 'Vulnerability type is required and must be a string'
        },
        description: {
          bsonType: 'string',
          description: 'Description must be a string'
        },
        severity: {
          enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
          description: 'Severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO'
        },
        status: {
          enum: ['PENDING', 'CONFIRMED', 'FALSE_POSITIVE', 'EXPLOITABLE', 'NOT_EXPLOITABLE'],
          description: 'Status must be one of: PENDING, CONFIRMED, FALSE_POSITIVE, EXPLOITABLE, NOT_EXPLOITABLE'
        },
        confidence: {
          enum: ['HIGH', 'MEDIUM', 'LOW'],
          description: 'Confidence must be one of: HIGH, MEDIUM, LOW'
        },
        priority: {
          enum: ['P0', 'P1', 'P2', 'P3'],
          description: 'Priority must be one of: P0, P1, P2, P3'
        },
        evidence: {
          bsonType: 'array',
          description: 'Evidence must be an array'
        },
        exploitation_steps: {
          bsonType: 'array',
          description: 'Exploitation steps must be an array'
        },
        impact: {
          bsonType: 'string',
          description: 'Impact must be a string'
        },
        remediation: {
          bsonType: 'string',
          description: 'Remediation must be a string'
        },
        mitigation_recommendations: {
          bsonType: 'array',
          description: 'Mitigation recommendations must be an array'
        },
        cve: {
          bsonType: 'string',
          description: 'CVE must be a string'
        },
        cvss_score: {
          bsonType: 'number',
          minimum: 0,
          maximum: 10,
          description: 'CVSS score must be a number between 0 and 10'
        },
        created_at: {
          bsonType: 'date',
          description: 'Created at is required and must be a date'
        },
        updated_at: {
          bsonType: 'date',
          description: 'Updated at must be a date'
        },
        sources: {
          bsonType: 'array',
          description: 'Sources must be an array'
        },
        report_id: {
          bsonType: 'string',
          description: 'Report ID must be a string'
        }
      }
    }
  }
});

db.createCollection('analyses', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['analysis_type', 'agent_name', 'report_id', 'created_at'],
      properties: {
        analysis_type: {
          enum: ['STATIC', 'DYNAMIC', 'TRIAGE'],
          description: 'Analysis type must be one of: STATIC, DYNAMIC, TRIAGE'
        },
        agent_name: {
          bsonType: 'string',
          description: 'Agent name is required and must be a string'
        },
        report_id: {
          bsonType: 'string',
          description: 'Report ID is required and must be a string'
        },
        vulnerability_ids: {
          bsonType: 'array',
          description: 'Vulnerability IDs must be an array'
        },
        configuration: {
          bsonType: 'object',
          description: 'Configuration must be an object'
        },
        results: {
          bsonType: 'object',
          description: 'Results must be an object'
        },
        created_at: {
          bsonType: 'date',
          description: 'Created at is required and must be a date'
        },
        started_at: {
          bsonType: 'date',
          description: 'Started at must be a date'
        },
        completed_at: {
          bsonType: 'date',
          description: 'Completed at must be a date'
        },
        execution_time_seconds: {
          bsonType: 'number',
          minimum: 0,
          description: 'Execution time must be a positive number'
        },
        context: {
          bsonType: 'object',
          description: 'Context must be an object'
        },
        error_message: {
          bsonType: 'string',
          description: 'Error message must be a string'
        }
      }
    }
  }
});

db.createCollection('triage_results', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['report_id', 'created_at'],
      properties: {
        report_id: {
          bsonType: 'string',
          description: 'Report ID is required and must be a string'
        },
        analysis_ids: {
          bsonType: 'array',
          description: 'Analysis IDs must be an array'
        },
        triage_summary: {
          bsonType: 'object',
          description: 'Triage summary must be an object'
        },
        severity_distribution: {
          bsonType: 'object',
          description: 'Severity distribution must be an object'
        },
        consolidated_vulnerability_ids: {
          bsonType: 'array',
          description: 'Consolidated vulnerability IDs must be an array'
        },
        created_at: {
          bsonType: 'date',
          description: 'Created at is required and must be a date'
        },
        analysis_completed_at: {
          bsonType: 'date',
          description: 'Analysis completed at must be a date'
        }
      }
    }
  }
});

// Crear índices para optimizar consultas
print('Creating indexes...');

// Índices para reports
db.reports.createIndex({ "file_path": 1 }, { unique: true });
db.reports.createIndex({ "created_at": -1 });
db.reports.createIndex({ "title": "text", "client": "text" });

// Índices para vulnerabilities
db.vulnerabilities.createIndex({ "report_id": 1 });
db.vulnerabilities.createIndex({ "severity": 1 });
db.vulnerabilities.createIndex({ "status": 1 });
db.vulnerabilities.createIndex({ "priority": 1 });
db.vulnerabilities.createIndex({ "created_at": -1 });
db.vulnerabilities.createIndex({ "name": "text", "description": "text" });
db.vulnerabilities.createIndex({ "report_id": 1, "severity": 1 });
db.vulnerabilities.createIndex({ "report_id": 1, "status": 1 });

// Índices para analyses
db.analyses.createIndex({ "report_id": 1 });
db.analyses.createIndex({ "analysis_type": 1 });
db.analyses.createIndex({ "agent_name": 1 });
db.analyses.createIndex({ "created_at": -1 });
db.analyses.createIndex({ "report_id": 1, "analysis_type": 1 });

// Índices para triage_results
db.triage_results.createIndex({ "report_id": 1 }, { unique: true });
db.triage_results.createIndex({ "created_at": -1 });

print('Database initialization completed successfully!');
print('Collections created: reports, vulnerabilities, analyses, triage_results');
print('User created: triage_user');
print('Indexes created for optimal query performance');
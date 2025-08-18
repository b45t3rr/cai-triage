#!/usr/bin/env python3
"""
Servicios de dominio

Este módulo contiene la lógica de negocio que no pertenece a una entidad específica
pero que es parte del dominio.
"""

import hashlib
import re
from typing import List, Dict, Tuple
from .entities import Vulnerability, SeverityLevel, Priority, ConfidenceLevel


class VulnerabilityDeduplicationService:
    """Servicio para detectar y consolidar vulnerabilidades duplicadas"""
    
    @staticmethod
    def calculate_vulnerability_hash(name: str, vulnerability_type: str) -> str:
        """Calcula un hash único para identificar vulnerabilidades duplicadas"""
        # Normalizar nombres para mejor correlación
        normalized_name = re.sub(r'[^\w\s]', '', name.lower().strip())
        normalized_type = re.sub(r'[^\w\s]', '', vulnerability_type.lower().strip())
        
        hash_input = f"{normalized_name}_{normalized_type}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:8]
    
    @staticmethod
    def are_vulnerabilities_similar(vuln1: Vulnerability, vuln2: Vulnerability, threshold: float = 0.8) -> bool:
        """Determina si dos vulnerabilidades son similares usando análisis semántico básico"""
        # Comparar hashes
        hash1 = VulnerabilityDeduplicationService.calculate_vulnerability_hash(vuln1.name, vuln1.vulnerability_type)
        hash2 = VulnerabilityDeduplicationService.calculate_vulnerability_hash(vuln2.name, vuln2.vulnerability_type)
        
        if hash1 == hash2:
            return True
        
        # Comparar similitud de nombres y tipos
        name_similarity = VulnerabilityDeduplicationService._calculate_text_similarity(vuln1.name, vuln2.name)
        type_similarity = VulnerabilityDeduplicationService._calculate_text_similarity(vuln1.vulnerability_type, vuln2.vulnerability_type)
        
        # Si ambos tienen alta similitud, considerarlos duplicados
        return name_similarity >= threshold and type_similarity >= threshold
    
    @staticmethod
    def _calculate_text_similarity(text1: str, text2: str) -> float:
        """Calcula similitud básica entre dos textos"""
        if not text1 or not text2:
            return 0.0
        
        # Normalizar textos
        norm1 = set(re.sub(r'[^\w\s]', '', text1.lower()).split())
        norm2 = set(re.sub(r'[^\w\s]', '', text2.lower()).split())
        
        if not norm1 or not norm2:
            return 0.0
        
        # Calcular similitud de Jaccard
        intersection = len(norm1.intersection(norm2))
        union = len(norm1.union(norm2))
        
        return intersection / union if union > 0 else 0.0
    
    @staticmethod
    def consolidate_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Consolida una lista de vulnerabilidades eliminando duplicados"""
        if not vulnerabilities:
            return []
        
        consolidated = []
        processed_hashes = set()
        
        for vuln in vulnerabilities:
            vuln_hash = VulnerabilityDeduplicationService.calculate_vulnerability_hash(vuln.name, vuln.vulnerability_type)
            
            # Buscar si ya existe una vulnerabilidad similar
            existing_vuln = None
            for existing in consolidated:
                if VulnerabilityDeduplicationService.are_vulnerabilities_similar(vuln, existing):
                    existing_vuln = existing
                    break
            
            if existing_vuln:
                # Consolidar con la existente
                VulnerabilityDeduplicationService._merge_vulnerabilities(existing_vuln, vuln)
            else:
                # Añadir como nueva vulnerabilidad
                consolidated.append(vuln)
                processed_hashes.add(vuln_hash)
        
        return consolidated
    
    @staticmethod
    def _merge_vulnerabilities(target: Vulnerability, source: Vulnerability) -> None:
        """Fusiona la información de dos vulnerabilidades similares"""
        # Usar la severidad más alta
        target.update_severity(source.severity)
        
        # Consolidar evidencia
        for evidence in source.evidence:
            target.add_evidence(evidence, f"merged_from_{source.id}")
        
        # Consolidar fuentes
        for source_name in source.sources:
            if source_name not in target.sources:
                target.sources.append(source_name)
        
        # Consolidar recomendaciones de mitigación
        for recommendation in source.mitigation_recommendations:
            if recommendation not in target.mitigation_recommendations:
                target.mitigation_recommendations.append(recommendation)
        
        # Usar la descripción más detallada
        if len(source.description) > len(target.description):
            target.description = source.description
        
        # Usar los pasos de explotación más detallados
        if len(source.exploitation_steps) > len(target.exploitation_steps):
            target.exploitation_steps = source.exploitation_steps
        
        # Usar el impacto más detallado
        if len(source.impact) > len(target.impact):
            target.impact = source.impact
        
        # Usar CVE si no existe
        if source.cve and not target.cve:
            target.cve = source.cve
        
        # Usar CVSS score más alto
        if source.cvss_score and (not target.cvss_score or source.cvss_score > target.cvss_score):
            target.cvss_score = source.cvss_score
        
        # Actualizar confianza basada en número de fuentes
        target.confidence = VulnerabilityDeduplicationService._calculate_consolidated_confidence(target)

    @staticmethod
    def _calculate_consolidated_confidence(vulnerability: Vulnerability) -> ConfidenceLevel:
        """Calcula el nivel de confianza basado en el número de fuentes y evidencia"""
        source_count = len(vulnerability.sources)
        evidence_count = len(vulnerability.evidence)
        
        if source_count >= 3 or evidence_count >= 5:
            return ConfidenceLevel.HIGH
        elif source_count >= 2 or evidence_count >= 3:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW


class VulnerabilityPriorityService:
    """Servicio para calcular prioridades de vulnerabilidades"""
    
    @staticmethod
    def calculate_priority(vulnerability: Vulnerability) -> Priority:
        """Calcula la prioridad de una vulnerabilidad"""
        severity_priority = VulnerabilityPriorityService._get_severity_priority(vulnerability.severity)
        has_exploit = bool(vulnerability.exploitation_steps)
        confidence_high = vulnerability.confidence == ConfidenceLevel.HIGH
        
        if severity_priority >= 4 and confidence_high:  # Critical + High confidence
            return Priority.P0
        elif severity_priority >= 3 and (confidence_high or has_exploit):  # High + (High confidence OR exploit)
            return Priority.P1
        elif severity_priority >= 2:  # Medium
            return Priority.P2
        else:  # Low
            return Priority.P3
    
    @staticmethod
    def _get_severity_priority(severity: SeverityLevel) -> int:
        """Retorna prioridad numérica para ordenar severidades"""
        severity_map = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0
        }
        return severity_map.get(severity, 0)


class VulnerabilityMitigationService:
    """Servicio para generar recomendaciones de mitigación"""
    
    @staticmethod
    def generate_mitigation_recommendations(vulnerability: Vulnerability) -> List[str]:
        """Genera recomendaciones de mitigación basadas en el tipo de vulnerabilidad"""
        recommendations = []
        
        vuln_type_lower = vulnerability.vulnerability_type.lower()
        vuln_name_lower = vulnerability.name.lower()
        
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
        
        elif 'csrf' in vuln_type_lower or 'cross-site request forgery' in vuln_name_lower:
            recommendations.extend([
                "Implementar tokens CSRF en todos los formularios",
                "Validar el header Referer",
                "Usar SameSite cookies",
                "Implementar verificación de origen"
            ])
        
        elif 'authentication' in vuln_type_lower or 'auth' in vuln_name_lower:
            recommendations.extend([
                "Implementar autenticación multifactor (MFA)",
                "Usar políticas de contraseñas robustas",
                "Implementar bloqueo de cuentas tras intentos fallidos",
                "Usar tokens de sesión seguros"
            ])
        
        elif 'authorization' in vuln_type_lower or 'access control' in vuln_name_lower:
            recommendations.extend([
                "Implementar controles de acceso basados en roles (RBAC)",
                "Aplicar principio de menor privilegio",
                "Validar permisos en cada operación",
                "Implementar auditoría de accesos"
            ])
        
        else:
            recommendations.extend([
                "Revisar y actualizar código vulnerable",
                "Implementar validación de entrada robusta",
                "Aplicar principios de seguridad por diseño",
                "Realizar pruebas de seguridad regulares"
            ])
        
        return recommendations
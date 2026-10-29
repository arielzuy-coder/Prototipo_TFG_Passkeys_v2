"""
Módulo de Threat Intelligence
UC-03: Integración con fuentes de inteligencia de amenazas

Este módulo implementa funcionalidades de threat intelligence para:
- Verificación de IPs maliciosas en listas negras públicas
- Detección de patrones de ataque conocidos
- Enriquecimiento contextual de evaluaciones de riesgo
- Integración con AbuseIPDB y otras fuentes públicas
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
import requests
import logging
import hashlib
import json

from models import AuditEvent, RiskEvaluation, Session as DBSession
from app import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threat-intelligence", tags=["Threat Intelligence"])


# ============================================
# CONFIGURACIÓN
# ============================================

# Cache en memoria para IPs verificadas (en producción usar Redis)
IP_REPUTATION_CACHE = {}  # {ip: {score, timestamp, sources}}
CACHE_DURATION = 3600  # 1 hora en segundos

# Lista de indicadores de amenaza conocidos
THREAT_INDICATORS = {
    'user_agents': [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit',
        'burp', 'dirbuster', 'acunetix', 'nessus'
    ],
    'suspicious_patterns': [
        'admin', 'root', 'test', 'backup', 'phpMyAdmin',
        '../', '..\\', '<script', 'union select', 'drop table'
    ]
}


# ============================================
# MODELOS PYDANTIC
# ============================================

class ThreatCheckRequest(BaseModel):
    """Solicitud de verificación de amenaza"""
    ip_address: str
    user_agent: Optional[str] = None
    additional_context: Optional[Dict[str, Any]] = None


class ThreatIntelligenceResponse(BaseModel):
    """Respuesta de análisis de amenaza"""
    ip_address: str
    is_malicious: bool
    threat_score: int  # 0-100
    confidence: str  # low, medium, high
    sources: List[Dict[str, Any]]
    indicators: List[str]
    recommendation: str
    checked_at: datetime


class IPReputationSummary(BaseModel):
    """Resumen de reputación de IP"""
    ip_address: str
    total_checks: int
    abuse_score: int
    is_whitelisted: bool
    is_blacklisted: bool
    country_code: Optional[str]
    isp: Optional[str]
    last_reported: Optional[datetime]


# ============================================
# FUNCIONES DE THREAT INTELLIGENCE
# ============================================

def check_ip_in_cache(ip_address: str) -> Optional[Dict[str, Any]]:
    """Verifica si la IP está en caché y si es válida"""
    if ip_address in IP_REPUTATION_CACHE:
        cached_data = IP_REPUTATION_CACHE[ip_address]
        if datetime.now().timestamp() - cached_data['timestamp'] < CACHE_DURATION:
            return cached_data
    return None


def check_abuseipdb(ip_address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Consulta AbuseIPDB para verificar reputación de IP
    
    Nota: Requiere API key de AbuseIPDB (gratuita hasta 1000 checks/día)
    Registrarse en: https://www.abuseipdb.com/register
    """
    
    if not api_key:
        # Sin API key, retornar datos mock para testing
        logger.warning(f"AbuseIPDB API key no configurada, usando datos simulados para {ip_address}")
        return {
            'ip': ip_address,
            'abuseConfidenceScore': 0,
            'isWhitelisted': False,
            'countryCode': 'XX',
            'usageType': 'Unknown',
            'isp': 'Unknown ISP',
            'totalReports': 0,
            'source': 'mock'
        }
    
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'ip': data.get('ipAddress'),
                'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                'isWhitelisted': data.get('isWhitelisted', False),
                'countryCode': data.get('countryCode'),
                'usageType': data.get('usageType'),
                'isp': data.get('isp'),
                'totalReports': data.get('totalReports', 0),
                'source': 'abuseipdb'
            }
        else:
            logger.error(f"Error en AbuseIPDB API: {response.status_code}")
            return {'ip': ip_address, 'abuseConfidenceScore': 0, 'source': 'error'}
    
    except Exception as e:
        logger.error(f"Excepción al consultar AbuseIPDB: {str(e)}")
        return {'ip': ip_address, 'abuseConfidenceScore': 0, 'source': 'error'}


def check_local_blacklist(ip_address: str, db: Session) -> Dict[str, Any]:
    """
    Verifica la IP contra una lista negra local basada en comportamiento
    """
    
    # Buscar eventos sospechosos de esta IP en los últimos 30 días
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    suspicious_events = db.query(AuditEvent).filter(
        AuditEvent.ip_address == ip_address,
        AuditEvent.timestamp >= thirty_days_ago,
        AuditEvent.event_type.in_(['login_failed', 'access_denied', 'suspicious_activity'])
    ).count()
    
    successful_events = db.query(AuditEvent).filter(
        AuditEvent.ip_address == ip_address,
        AuditEvent.timestamp >= thirty_days_ago,
        AuditEvent.event_type.in_(['login_success', 'access_granted'])
    ).count()
    
    # Calcular score local basado en el ratio de eventos
    total_events = suspicious_events + successful_events
    if total_events == 0:
        local_score = 0
    else:
        local_score = int((suspicious_events / total_events) * 100)
    
    return {
        'ip': ip_address,
        'local_threat_score': local_score,
        'suspicious_events': suspicious_events,
        'successful_events': successful_events,
        'source': 'local_blacklist'
    }


def detect_threat_indicators(user_agent: Optional[str], context: Optional[Dict] = None) -> List[str]:
    """
    Detecta indicadores de amenaza en user agent y contexto
    """
    
    indicators = []
    
    if user_agent:
        user_agent_lower = user_agent.lower()
        
        # Detectar herramientas de scanning
        for tool in THREAT_INDICATORS['user_agents']:
            if tool in user_agent_lower:
                indicators.append(f"Scanning tool detected: {tool}")
        
        # Detectar patrones sospechosos
        for pattern in THREAT_INDICATORS['suspicious_patterns']:
            if pattern in user_agent_lower:
                indicators.append(f"Suspicious pattern: {pattern}")
    
    # Analizar contexto adicional si está disponible
    if context:
        # Detectar múltiples intentos fallidos
        if context.get('failed_attempts', 0) > 5:
            indicators.append("Multiple failed authentication attempts")
        
        # Detectar cambios bruscos de geolocalización
        if context.get('location_change_distance', 0) > 1000:
            indicators.append("Impossible travel detected")
        
        # Detectar uso de Tor/VPN conocidos
        if context.get('is_tor', False) or context.get('is_vpn', False):
            indicators.append("Anonymization service detected")
    
    return indicators


def calculate_threat_score(
    abuseipdb_data: Dict,
    local_data: Dict,
    indicators: List[str]
) -> tuple:
    """
    Calcula un score de amenaza consolidado (0-100) y nivel de confianza
    """
    
    # Ponderar diferentes fuentes
    abuse_score = abuseipdb_data.get('abuseConfidenceScore', 0) * 0.5
    local_score = local_data.get('local_threat_score', 0) * 0.3
    indicator_score = min(len(indicators) * 20, 100) * 0.2
    
    total_score = int(abuse_score + local_score + indicator_score)
    
    # Determinar confianza
    sources_count = 0
    if abuseipdb_data.get('totalReports', 0) > 0:
        sources_count += 1
    if local_data.get('suspicious_events', 0) > 0:
        sources_count += 1
    if len(indicators) > 0:
        sources_count += 1
    
    if sources_count >= 2:
        confidence = "high"
    elif sources_count == 1:
        confidence = "medium"
    else:
        confidence = "low"
    
    return total_score, confidence


# ============================================
# ENDPOINTS
# ============================================

@router.post("/check", response_model=ThreatIntelligenceResponse)
async def check_threat(
    request: ThreatCheckRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    UC-03: Verificar si una IP/contexto representa una amenaza
    
    Consulta múltiples fuentes de threat intelligence y retorna un análisis consolidado
    """
    
    try:
        # Verificar caché
        cached_result = check_ip_in_cache(request.ip_address)
        if cached_result:
            logger.info(f"Usando resultado en caché para IP: {request.ip_address}")
            return ThreatIntelligenceResponse(
                ip_address=request.ip_address,
                is_malicious=cached_result['is_malicious'],
                threat_score=cached_result['threat_score'],
                confidence=cached_result['confidence'],
                sources=cached_result['sources'],
                indicators=cached_result['indicators'],
                recommendation=cached_result['recommendation'],
                checked_at=datetime.fromtimestamp(cached_result['timestamp'])
            )
        
        # Consultar fuentes externas
        abuseipdb_data = check_abuseipdb(request.ip_address)
        
        # Consultar lista negra local
        local_data = check_local_blacklist(request.ip_address, db)
        
        # Detectar indicadores de amenaza
        indicators = detect_threat_indicators(
            request.user_agent,
            request.additional_context
        )
        
        # Calcular score consolidado
        threat_score, confidence = calculate_threat_score(
            abuseipdb_data, local_data, indicators
        )
        
        # Determinar si es malicioso
        is_malicious = threat_score >= 70
        
        # Preparar fuentes
        sources = [
            {
                'name': 'AbuseIPDB',
                'score': abuseipdb_data.get('abuseConfidenceScore', 0),
                'reports': abuseipdb_data.get('totalReports', 0)
            },
            {
                'name': 'Local Blacklist',
                'score': local_data.get('local_threat_score', 0),
                'suspicious_events': local_data.get('suspicious_events', 0)
            }
        ]
        
        # Generar recomendación
        if threat_score >= 90:
            recommendation = "BLOCK: Alto riesgo de amenaza detectado"
        elif threat_score >= 70:
            recommendation = "CHALLENGE: Requiere autenticación adicional (step-up)"
        elif threat_score >= 40:
            recommendation = "MONITOR: Monitorear actividad de cerca"
        else:
            recommendation = "ALLOW: Riesgo bajo, permitir acceso"
        
        # Guardar en caché
        cache_entry = {
            'is_malicious': is_malicious,
            'threat_score': threat_score,
            'confidence': confidence,
            'sources': sources,
            'indicators': indicators,
            'recommendation': recommendation,
            'timestamp': datetime.now().timestamp()
        }
        IP_REPUTATION_CACHE[request.ip_address] = cache_entry
        
        # Registrar verificación en auditoría (background)
        background_tasks.add_task(
            log_threat_check,
            db,
            request.ip_address,
            threat_score,
            is_malicious
        )
        
        return ThreatIntelligenceResponse(
            ip_address=request.ip_address,
            is_malicious=is_malicious,
            threat_score=threat_score,
            confidence=confidence,
            sources=sources,
            indicators=indicators,
            recommendation=recommendation,
            checked_at=datetime.now()
        )
    
    except Exception as e:
        logger.error(f"Error al verificar amenaza: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error en verificación de amenaza: {str(e)}")


@router.get("/reputation/{ip_address}", response_model=IPReputationSummary)
async def get_ip_reputation(
    ip_address: str,
    db: Session = Depends(get_db)
):
    """
    UC-03: Obtener resumen de reputación histórica de una IP
    """
    
    try:
        # Consultar AbuseIPDB
        abuse_data = check_abuseipdb(ip_address)
        
        # Consultar datos locales
        local_data = check_local_blacklist(ip_address, db)
        
        # Buscar último reporte
        last_event = db.query(AuditEvent).filter(
            AuditEvent.ip_address == ip_address,
            AuditEvent.event_type.in_(['suspicious_activity', 'access_denied'])
        ).order_by(desc(AuditEvent.timestamp)).first()
        
        return IPReputationSummary(
            ip_address=ip_address,
            total_checks=abuse_data.get('totalReports', 0),
            abuse_score=abuse_data.get('abuseConfidenceScore', 0),
            is_whitelisted=abuse_data.get('isWhitelisted', False),
            is_blacklisted=local_data.get('local_threat_score', 0) >= 70,
            country_code=abuse_data.get('countryCode'),
            isp=abuse_data.get('isp'),
            last_reported=last_event.timestamp if last_event else None
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener reputación: {str(e)}")


@router.get("/indicators/recent")
async def get_recent_threat_indicators(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    UC-03: Obtener indicadores de amenaza recientes
    
    Útil para dashboards de seguridad
    """
    
    try:
        since = datetime.now() - timedelta(hours=hours)
        
        # IPs con múltiples fallos de autenticación
        suspicious_ips = db.query(
            AuditEvent.ip_address,
            func.count(AuditEvent.id).label('failed_attempts')
        ).filter(
            AuditEvent.timestamp >= since,
            AuditEvent.event_type == 'login_failed',
            AuditEvent.ip_address.isnot(None)
        ).group_by(AuditEvent.ip_address).having(
            func.count(AuditEvent.id) >= 5
        ).all()
        
        # User agents sospechosos
        suspicious_agents = db.query(
            AuditEvent.user_agent,
            func.count(AuditEvent.id).label('count')
        ).filter(
            AuditEvent.timestamp >= since,
            AuditEvent.user_agent.isnot(None)
        ).group_by(AuditEvent.user_agent).all()
        
        flagged_agents = []
        for agent, count in suspicious_agents:
            if agent and any(tool in agent.lower() for tool in THREAT_INDICATORS['user_agents']):
                flagged_agents.append({'user_agent': agent, 'count': count})
        
        return {
            'period_hours': hours,
            'suspicious_ips': [
                {'ip': ip, 'failed_attempts': count}
                for ip, count in suspicious_ips
            ],
            'suspicious_user_agents': flagged_agents,
            'generated_at': datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener indicadores: {str(e)}")


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def log_threat_check(db: Session, ip_address: str, threat_score: int, is_malicious: bool):
    """
    Registra la verificación de amenaza en auditoría (ejecutado en background)
    """
    try:
        audit_event = AuditEvent(
            event_type='threat_intelligence_check',
            ip_address=ip_address,
            event_data={
                'threat_score': threat_score,
                'is_malicious': is_malicious,
                'checked_at': datetime.now().isoformat()
            }
        )
        db.add(audit_event)
        db.commit()
    except Exception as e:
        logger.error(f"Error al registrar verificación de amenaza: {str(e)}")
        db.rollback()


@router.post("/enrich-risk-evaluation")
async def enrich_risk_with_threat_intel(
    session_id: str,
    db: Session = Depends(get_db)
):
    """
    UC-03: Enriquecer evaluación de riesgo con datos de threat intelligence
    
    Actualiza el score de riesgo de una sesión basado en threat intel
    """
    
    try:
        # Buscar sesión
        session = db.query(DBSession).filter(DBSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Sesión no encontrada")
        
        # Verificar amenaza
        threat_check = check_abuseipdb(session.ip_address)
        local_check = check_local_blacklist(session.ip_address, db)
        
        # Calcular ajuste de riesgo
        threat_adjustment = 0
        if threat_check.get('abuseConfidenceScore', 0) > 50:
            threat_adjustment += 20
        if local_check.get('local_threat_score', 0) > 50:
            threat_adjustment += 15
        
        # Actualizar risk score de la sesión
        new_risk_score = min(float(session.risk_score) + threat_adjustment, 100)
        session.risk_score = new_risk_score
        
        # Crear evaluación de riesgo enriquecida
        enriched_eval = RiskEvaluation(
            session_id=session.id,
            user_id=session.user_id,
            risk_score=new_risk_score,
            factors={
                'original_score': float(session.risk_score),
                'threat_intel_adjustment': threat_adjustment,
                'abuseipdb_score': threat_check.get('abuseConfidenceScore', 0),
                'local_threat_score': local_check.get('local_threat_score', 0)
            },
            decision='enriched_by_threat_intel'
        )
        
        db.add(enriched_eval)
        db.commit()
        
        return {
            'session_id': str(session.id),
            'original_risk_score': float(session.risk_score) - threat_adjustment,
            'threat_adjustment': threat_adjustment,
            'new_risk_score': float(new_risk_score),
            'recommendation': 'step_up_required' if new_risk_score >= 70 else 'allow'
        }
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al enriquecer evaluación: {str(e)}")

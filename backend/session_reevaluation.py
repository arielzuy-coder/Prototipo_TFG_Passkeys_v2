"""
Módulo de Reevaluación Continua de Sesiones
UC-03: Verificación continua Zero Trust

Este módulo implementa la reevaluación periódica de sesiones activas:
- Verificación continua de contexto de sesión
- Detección de cambios anómalos (geolocalización, dispositivo, comportamiento)
- Ajuste dinámico de niveles de confianza
- Triggers automáticos de step-up authentication
- Revocación automática de sesiones comprometidas
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
import logging
import asyncio
from geopy.distance import geodesic
import hashlib

from models import Session as DBSession, User, Device, RiskEvaluation, AuditEvent
from app import get_db
from risk.risk_engine import RiskEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/session-monitoring", tags=["Session Monitoring"])

# Instancia del motor de riesgo
risk_engine = RiskEngine()


# ============================================
# CONFIGURACIÓN
# ============================================

# Intervalos de reevaluación (en segundos)
REEVALUATION_INTERVALS = {
    'high_risk': 300,      # 5 minutos para sesiones de alto riesgo
    'medium_risk': 900,    # 15 minutos para riesgo medio
    'low_risk': 1800       # 30 minutos para riesgo bajo
}

# Umbrales de cambio para triggers
CHANGE_THRESHOLDS = {
    'location_km': 100,        # Cambio de ubicación > 100km
    'ip_change': True,         # Cambio de IP
    'device_change': True,     # Cambio de dispositivo
    'user_agent_change': True, # Cambio de user agent
    'max_risk_increase': 30    # Incremento máximo aceptable de riesgo
}


# ============================================
# MODELOS PYDANTIC
# ============================================

class SessionContextUpdate(BaseModel):
    """Actualización de contexto de sesión"""
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None
    additional_context: Optional[Dict[str, Any]] = None


class ReevaluationResult(BaseModel):
    """Resultado de reevaluación de sesión"""
    session_id: str
    previous_risk_score: float
    current_risk_score: float
    risk_change: float
    anomalies_detected: List[str]
    action_required: str  # 'none', 'monitor', 'stepup', 'revoke'
    confidence: str
    reevaluated_at: datetime


class SessionHealthStatus(BaseModel):
    """Estado de salud de una sesión"""
    session_id: str
    user_id: str
    is_active: bool
    risk_score: float
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    last_reevaluation: datetime
    next_reevaluation: datetime
    anomalies_count: int
    recommendations: List[str]


class ActiveSessionsSummary(BaseModel):
    """Resumen de sesiones activas"""
    total_sessions: int
    by_risk_level: Dict[str, int]
    high_risk_sessions: List[Dict[str, Any]]
    sessions_requiring_action: int


# ============================================
# FUNCIONES DE ANÁLISIS
# ============================================

def detect_location_anomaly(
    session: DBSession,
    new_location: Optional[str],
    db: Session
) -> tuple:
    """
    Detecta cambios anómalos en la geolocalización
    Retorna: (es_anómalo, distancia_km, descripción)
    """
    
    if not new_location or not session.location:
        return False, 0, None
    
    try:
        # Parsear coordenadas (formato: "lat,lon")
        old_coords = tuple(map(float, session.location.split(',')))
        new_coords = tuple(map(float, new_location.split(',')))
        
        # Calcular distancia
        distance_km = geodesic(old_coords, new_coords).kilometers
        
        # Calcular tiempo transcurrido
        time_diff = (datetime.now() - session.created_at).total_seconds() / 3600  # en horas
        
        # Detectar viaje imposible (velocidad > 800 km/h)
        if time_diff > 0:
            velocity = distance_km / time_diff
            if velocity > 800:
                return True, distance_km, f"Impossible travel: {velocity:.0f} km/h"
        
        # Detectar cambio significativo de ubicación
        if distance_km > CHANGE_THRESHOLDS['location_km']:
            return True, distance_km, f"Significant location change: {distance_km:.0f} km"
        
        return False, distance_km, None
    
    except Exception as e:
        logger.error(f"Error al calcular distancia: {str(e)}")
        return False, 0, None


def detect_device_anomaly(
    session: DBSession,
    new_user_agent: Optional[str],
    db: Session
) -> tuple:
    """
    Detecta cambios en el dispositivo o user agent
    Retorna: (es_anómalo, descripción)
    """
    
    if not new_user_agent:
        return False, None
    
    # Comparar user agents
    if session.user_agent and new_user_agent != session.user_agent:
        return True, "User agent changed during session"
    
    # Verificar device fingerprint si está disponible
    if session.device_id:
        device = db.query(Device).filter(Device.id == session.device_id).first()
        if device:
            # Aquí podrías implementar detección de fingerprint más sofisticada
            pass
    
    return False, None


def detect_behavioral_anomalies(
    session: DBSession,
    context: Dict[str, Any],
    db: Session
) -> List[str]:
    """
    Detecta anomalías comportamentales basadas en patrones históricos
    """
    
    anomalies = []
    
    # Verificar horario inusual
    current_hour = datetime.now().hour
    if 'typical_hours' in context:
        typical_hours = context['typical_hours']
        if current_hour not in typical_hours:
            anomalies.append(f"Access at unusual hour: {current_hour}:00")
    
    # Verificar frecuencia de accesos
    if 'access_count' in context:
        if context['access_count'] > context.get('avg_access_count', 10) * 3:
            anomalies.append("Abnormally high access frequency")
    
    # Verificar patrones de recursos accedidos
    if 'accessed_resources' in context:
        if context.get('sensitive_resource_access', 0) > 5:
            anomalies.append("Multiple sensitive resource access attempts")
    
    return anomalies


def calculate_next_reevaluation(risk_score: float) -> datetime:
    """
    Calcula el próximo momento de reevaluación según el nivel de riesgo
    """
    
    if risk_score >= 70:
        interval = REEVALUATION_INTERVALS['high_risk']
    elif risk_score >= 40:
        interval = REEVALUATION_INTERVALS['medium_risk']
    else:
        interval = REEVALUATION_INTERVALS['low_risk']
    
    return datetime.now() + timedelta(seconds=interval)


def determine_action(
    risk_change: float,
    anomalies: List[str],
    current_risk: float
) -> str:
    """
    Determina la acción requerida basada en cambios detectados
    """
    
    # Revocación inmediata
    if current_risk >= 90 or len(anomalies) >= 3:
        return 'revoke'
    
    # Step-up requerido
    if current_risk >= 70 or risk_change > CHANGE_THRESHOLDS['max_risk_increase']:
        return 'stepup'
    
    # Monitoreo cercano
    if current_risk >= 40 or len(anomalies) > 0:
        return 'monitor'
    
    # Sin acción necesaria
    return 'none'


# ============================================
# ENDPOINTS
# ============================================

@router.post("/reevaluate", response_model=ReevaluationResult)
async def reevaluate_session(
    update: SessionContextUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    UC-03: Reevaluar una sesión activa con contexto actualizado
    
    Función principal de verificación continua Zero Trust
    """
    
    try:
        # Buscar sesión
        session = db.query(DBSession).filter(
            DBSession.id == update.session_id,
            DBSession.revoked == False
        ).first()
        
        if not session:
            raise HTTPException(status_code=404, detail="Sesión no encontrada o revocada")
        
        # Verificar si la sesión ha expirado
        if session.expires_at < datetime.now():
            raise HTTPException(status_code=401, detail="Sesión expirada")
        
        previous_risk = float(session.risk_score)
        anomalies = []
        
        # Detectar anomalías de ubicación
        if update.location:
            location_anomaly, distance, description = detect_location_anomaly(
                session, update.location, db
            )
            if location_anomaly:
                anomalies.append(description)
        
        # Detectar anomalías de dispositivo
        if update.user_agent:
            device_anomaly, description = detect_device_anomaly(
                session, update.user_agent, db
            )
            if device_anomaly:
                anomalies.append(description)
        
        # Detectar cambio de IP
        if update.ip_address and update.ip_address != session.ip_address:
            anomalies.append(f"IP address changed: {session.ip_address} -> {update.ip_address}")
        
        # Detectar anomalías comportamentales
        if update.additional_context:
            behavioral_anomalies = detect_behavioral_anomalies(
                session, update.additional_context, db
            )
            anomalies.extend(behavioral_anomalies)
        
        # Recalcular riesgo usando el risk engine
        context = {
            'ip_address': update.ip_address or session.ip_address,
            'user_agent': update.user_agent or session.user_agent,
            'location': update.location or session.location,
            'device_id': str(session.device_id) if session.device_id else None,
            'session_age': (datetime.now() - session.created_at).total_seconds(),
            'anomalies_detected': len(anomalies)
        }
        
        if update.additional_context:
            context.update(update.additional_context)
        
        new_risk_score = risk_engine.evaluate_risk(context)
        risk_change = new_risk_score - previous_risk
        
        # Determinar acción requerida
        action = determine_action(risk_change, anomalies, new_risk_score)
        
        # Actualizar sesión
        session.risk_score = new_risk_score
        if update.ip_address:
            session.ip_address = update.ip_address
        if update.user_agent:
            session.user_agent = update.user_agent
        if update.location:
            session.location = update.location
        
        # Si requiere revocación, revocar la sesión
        if action == 'revoke':
            session.revoked = True
            logger.warning(f"Sesión {session.id} revocada por alto riesgo: {new_risk_score}")
        
        # Crear registro de evaluación
        evaluation = RiskEvaluation(
            session_id=session.id,
            user_id=session.user_id,
            risk_score=new_risk_score,
            factors={
                'previous_risk': previous_risk,
                'anomalies': anomalies,
                'context_changes': {
                    'ip_changed': update.ip_address != session.ip_address if update.ip_address else False,
                    'location_changed': update.location != session.location if update.location else False
                }
            },
            decision=action
        )
        
        db.add(evaluation)
        db.commit()
        
        # Registrar en auditoría (background)
        background_tasks.add_task(
            log_reevaluation,
            db,
            session.id,
            previous_risk,
            new_risk_score,
            action,
            anomalies
        )
        
        # Determinar confianza
        confidence = "high" if len(anomalies) >= 2 else "medium" if len(anomalies) == 1 else "low"
        
        return ReevaluationResult(
            session_id=str(session.id),
            previous_risk_score=previous_risk,
            current_risk_score=new_risk_score,
            risk_change=risk_change,
            anomalies_detected=anomalies,
            action_required=action,
            confidence=confidence,
            reevaluated_at=datetime.now()
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en reevaluación de sesión: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error en reevaluación: {str(e)}")


@router.get("/session/{session_id}/health", response_model=SessionHealthStatus)
async def get_session_health(
    session_id: str,
    db: Session = Depends(get_db)
):
    """
    UC-03: Obtener estado de salud de una sesión específica
    """
    
    try:
        session = db.query(DBSession).filter(DBSession.id == session_id).first()
        
        if not session:
            raise HTTPException(status_code=404, detail="Sesión no encontrada")
        
        # Contar evaluaciones recientes
        recent_evaluations = db.query(RiskEvaluation).filter(
            RiskEvaluation.session_id == session_id,
            RiskEvaluation.evaluated_at >= datetime.now() - timedelta(hours=1)
        ).count()
        
        # Contar anomalías detectadas
        anomaly_count = db.query(RiskEvaluation).filter(
            RiskEvaluation.session_id == session_id,
            RiskEvaluation.decision.in_(['stepup', 'revoke', 'monitor'])
        ).count()
        
        # Determinar nivel de riesgo
        risk_score = float(session.risk_score)
        if risk_score >= 70:
            risk_level = 'critical' if risk_score >= 90 else 'high'
        elif risk_score >= 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Última reevaluación
        last_eval = db.query(RiskEvaluation).filter(
            RiskEvaluation.session_id == session_id
        ).order_by(desc(RiskEvaluation.evaluated_at)).first()
        
        last_reevaluation = last_eval.evaluated_at if last_eval else session.created_at
        
        # Próxima reevaluación
        next_reevaluation = calculate_next_reevaluation(risk_score)
        
        # Generar recomendaciones
        recommendations = []
        if session.revoked:
            recommendations.append("Sesión revocada - requiere reautenticación")
        elif risk_score >= 70:
            recommendations.append("Requiere step-up authentication inmediato")
        elif risk_score >= 40:
            recommendations.append("Monitorear actividad de cerca")
        elif anomaly_count > 3:
            recommendations.append("Múltiples anomalías detectadas - considerar reevaluación")
        
        if session.expires_at < datetime.now() + timedelta(minutes=5):
            recommendations.append("Sesión próxima a expirar")
        
        return SessionHealthStatus(
            session_id=str(session.id),
            user_id=str(session.user_id),
            is_active=not session.revoked and session.expires_at > datetime.now(),
            risk_score=risk_score,
            risk_level=risk_level,
            last_reevaluation=last_reevaluation,
            next_reevaluation=next_reevaluation,
            anomalies_count=anomaly_count,
            recommendations=recommendations
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estado: {str(e)}")


@router.get("/active-sessions/summary", response_model=ActiveSessionsSummary)
async def get_active_sessions_summary(
    db: Session = Depends(get_db)
):
    """
    UC-03: Obtener resumen de todas las sesiones activas
    
    Útil para dashboard de monitoreo de seguridad
    """
    
    try:
        # Sesiones activas (no revocadas y no expiradas)
        active_sessions = db.query(DBSession).filter(
            DBSession.revoked == False,
            DBSession.expires_at > datetime.now()
        ).all()
        
        total = len(active_sessions)
        
        # Contar por nivel de riesgo
        by_risk_level = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'critical': 0
        }
        
        high_risk_list = []
        requiring_action = 0
        
        for session in active_sessions:
            risk_score = float(session.risk_score)
            
            if risk_score >= 90:
                by_risk_level['critical'] += 1
                requiring_action += 1
                high_risk_list.append({
                    'session_id': str(session.id),
                    'user_id': str(session.user_id),
                    'risk_score': risk_score,
                    'ip_address': session.ip_address
                })
            elif risk_score >= 70:
                by_risk_level['high'] += 1
                requiring_action += 1
                high_risk_list.append({
                    'session_id': str(session.id),
                    'user_id': str(session.user_id),
                    'risk_score': risk_score,
                    'ip_address': session.ip_address
                })
            elif risk_score >= 40:
                by_risk_level['medium'] += 1
            else:
                by_risk_level['low'] += 1
        
        return ActiveSessionsSummary(
            total_sessions=total,
            by_risk_level=by_risk_level,
            high_risk_sessions=high_risk_list,
            sessions_requiring_action=requiring_action
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener resumen: {str(e)}")


@router.post("/batch-reevaluate")
async def batch_reevaluate_sessions(
    background_tasks: BackgroundTasks,
    risk_threshold: float = 40.0,
    db: Session = Depends(get_db)
):
    """
    UC-03: Reevaluar en lote todas las sesiones activas que cumplan criterios
    
    Ejecuta reevaluación periódica de todas las sesiones de riesgo medio/alto
    """
    
    try:
        # Buscar sesiones activas con riesgo >= threshold
        sessions = db.query(DBSession).filter(
            DBSession.revoked == False,
            DBSession.expires_at > datetime.now(),
            DBSession.risk_score >= risk_threshold
        ).all()
        
        # Encolar reevaluaciones en background
        reevaluated_count = 0
        for session in sessions:
            background_tasks.add_task(
                reevaluate_session_background,
                session.id,
                db
            )
            reevaluated_count += 1
        
        return {
            'message': f'Reevaluación en lote iniciada',
            'sessions_queued': reevaluated_count,
            'risk_threshold': risk_threshold,
            'initiated_at': datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en reevaluación por lote: {str(e)}")


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def log_reevaluation(
    db: Session,
    session_id: str,
    previous_risk: float,
    new_risk: float,
    action: str,
    anomalies: List[str]
):
    """
    Registra reevaluación en auditoría (ejecutado en background)
    """
    try:
        session = db.query(DBSession).filter(DBSession.id == session_id).first()
        if not session:
            return
        
        audit_event = AuditEvent(
            user_id=session.user_id,
            session_id=session.id,
            event_type='session_reevaluated',
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            event_data={
                'previous_risk_score': previous_risk,
                'new_risk_score': new_risk,
                'risk_change': new_risk - previous_risk,
                'action_required': action,
                'anomalies': anomalies,
                'reevaluated_at': datetime.now().isoformat()
            }
        )
        db.add(audit_event)
        db.commit()
    except Exception as e:
        logger.error(f"Error al registrar reevaluación: {str(e)}")
        db.rollback()


async def reevaluate_session_background(session_id: str, db: Session):
    """
    Reevalúa una sesión en background (para batch processing)
    """
    try:
        session = db.query(DBSession).filter(DBSession.id == session_id).first()
        if not session or session.revoked:
            return
        
        # Construir contexto desde datos de sesión
        context = {
            'ip_address': session.ip_address,
            'user_agent': session.user_agent,
            'location': session.location,
            'session_age': (datetime.now() - session.created_at).total_seconds()
        }
        
        # Recalcular riesgo
        new_risk = risk_engine.evaluate_risk(context)
        
        # Actualizar si hay cambio significativo
        if abs(new_risk - float(session.risk_score)) > 10:
            session.risk_score = new_risk
            
            evaluation = RiskEvaluation(
                session_id=session.id,
                user_id=session.user_id,
                risk_score=new_risk,
                factors={'reevaluation_type': 'batch', 'context': context},
                decision='updated'
            )
            db.add(evaluation)
            db.commit()
            
            logger.info(f"Sesión {session_id} reevaluada: nuevo riesgo {new_risk}")
    
    except Exception as e:
        logger.error(f"Error en reevaluación background: {str(e)}")
        db.rollback()

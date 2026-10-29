"""
Módulo de Auditoría y Reportes
UC-06: Exportación CSV/JSON, Reportes Agregados, Filtros Avanzados
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc, asc, create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import csv
import json
import io
import uuid
from fastapi.responses import StreamingResponse
import logging

from models import AuditEvent, User, Session as DBSession, RiskEvaluation, Passkey
from config import settings

# Configurar logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["Auditoría y Reportes"])

# Configurar la base de datos independientemente
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency para obtener DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================
# MODELOS PYDANTIC
# ============================================

class ReportFilters(BaseModel):
    """Filtros avanzados para reportes de auditoría"""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    event_types: Optional[List[str]] = None
    user_ids: Optional[List[str]] = None
    ip_addresses: Optional[List[str]] = None
    risk_score_min: Optional[float] = None
    risk_score_max: Optional[float] = None
    limit: Optional[int] = 100
    offset: Optional[int] = 0
    sort_by: Optional[str] = "timestamp"
    sort_order: Optional[str] = "desc"


class AggregatedReport(BaseModel):
    """Modelo para reportes agregados"""
    period: str
    total_events: int
    unique_users: int
    total_logins: int
    failed_logins: int
    stepup_challenges: int
    high_risk_events: int
    avg_risk_score: float
    event_type_breakdown: Dict[str, int]
    top_ips: List[Dict[str, Any]]
    hourly_distribution: List[Dict[str, Any]]


class ExportRequest(BaseModel):
    """Solicitud de exportación de datos"""
    format: str  # 'csv' o 'json'
    filters: Optional[ReportFilters] = None
    include_fields: Optional[List[str]] = None


# ============================================
# FUNCIONES AUXILIARES
# ============================================

def apply_filters(query, filters: ReportFilters):
    """Aplica filtros avanzados a una consulta de auditoría"""
    
    if filters.start_date:
        query = query.filter(AuditEvent.timestamp >= filters.start_date)
    
    if filters.end_date:
        query = query.filter(AuditEvent.timestamp <= filters.end_date)
    
    if filters.event_types:
        query = query.filter(AuditEvent.event_type.in_(filters.event_types))
    
    if filters.user_ids:
        query = query.filter(AuditEvent.user_id.in_(filters.user_ids))
    
    if filters.ip_addresses:
        query = query.filter(AuditEvent.ip_address.in_(filters.ip_addresses))
    
    # Ordenamiento
    if filters.sort_order == "asc":
        query = query.order_by(asc(getattr(AuditEvent, filters.sort_by)))
    else:
        query = query.order_by(desc(getattr(AuditEvent, filters.sort_by)))
    
    return query


def generate_csv(events: List[AuditEvent], include_fields: Optional[List[str]] = None) -> str:
    """Genera contenido CSV desde eventos de auditoría - VERSIÓN CORREGIDA"""
    
    output = io.StringIO()
    
    # Definir campos por defecto
    default_fields = ['id', 'timestamp', 'event_type', 'user_id', 'ip_address', 'user_agent']
    fields = include_fields if include_fields else default_fields
    
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    
    # Log para debug
    logger.info(f"Generando CSV con {len(events)} eventos")
    
    for event in events:
        row = {}
        for field in fields:
            try:
                value = getattr(event, field, None)
                
                # Convertir tipos especiales a string
                if isinstance(value, datetime):
                    value = value.isoformat()
                elif isinstance(value, uuid.UUID):
                    value = str(value)
                elif isinstance(value, dict):
                    value = json.dumps(value)
                elif value is None:
                    value = ''
                else:
                    value = str(value)
                
                row[field] = value
            except Exception as e:
                logger.error(f"Error procesando campo {field}: {str(e)}")
                row[field] = ''
        
        writer.writerow(row)
    
    csv_content = output.getvalue()
    logger.info(f"CSV generado con {len(csv_content)} caracteres")
    
    return csv_content


def generate_json(events: List[AuditEvent], include_fields: Optional[List[str]] = None) -> str:
    """Genera contenido JSON desde eventos de auditoría - VERSIÓN CORREGIDA"""
    
    result = []
    default_fields = ['id', 'timestamp', 'event_type', 'user_id', 'ip_address', 'user_agent', 'event_data']
    fields = include_fields if include_fields else default_fields
    
    logger.info(f"Generando JSON con {len(events)} eventos")
    
    for event in events:
        item = {}
        for field in fields:
            try:
                value = getattr(event, field, None)
                
                # Convertir tipos especiales
                if isinstance(value, datetime):
                    value = value.isoformat()
                elif isinstance(value, uuid.UUID):
                    value = str(value)
                elif value is None:
                    value = None
                
                item[field] = value
            except Exception as e:
                logger.error(f"Error procesando campo {field}: {str(e)}")
                item[field] = None
        
        result.append(item)
    
    json_content = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    logger.info(f"JSON generado con {len(json_content)} caracteres")
    
    return json_content


# ============================================
# ENDPOINTS - EXPORTACIÓN
# ============================================

@router.post("/export")
async def export_audit_data(
    export_request: ExportRequest,
    db: Session = Depends(get_db)
):
    """
    UC-06: Exportar datos de auditoría en formato CSV o JSON
    
    CRÍTICO: Permite exportar registros de eventos para cumplimiento y análisis externo
    """
    
    try:
        logger.info(f"Iniciando exportación en formato {export_request.format}")
        
        # Construir consulta base
        query = db.query(AuditEvent)
        
        # Aplicar filtros si existen
        if export_request.filters:
            logger.info(f"Aplicando filtros: {export_request.filters}")
            query = apply_filters(query, export_request.filters)
            
            # Aplicar límite y offset
            limit = export_request.filters.limit or 100
            offset = export_request.filters.offset or 0
            
            query = query.limit(limit).offset(offset)
        else:
            # Límite por defecto para evitar exportaciones masivas
            query = query.limit(10000)
        
        # Ejecutar consulta
        events = query.all()
        logger.info(f"Consulta ejecutada: {len(events)} eventos encontrados")
        
        if len(events) == 0:
            logger.warning("No se encontraron eventos para exportar")
            # Retornar archivo vacío con mensaje
            if export_request.format.lower() == 'csv':
                content = "id,timestamp,event_type,user_id,ip_address,user_agent\n# No hay datos para exportar"
            else:
                content = json.dumps({"message": "No hay datos para exportar", "events": []})
        else:
            # Generar contenido según formato
            if export_request.format.lower() == 'csv':
                content = generate_csv(events, export_request.include_fields)
                media_type = 'text/csv'
                filename = f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            elif export_request.format.lower() == 'json':
                content = generate_json(events, export_request.include_fields)
                media_type = 'application/json'
                filename = f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            else:
                raise HTTPException(status_code=400, detail="Formato no soportado. Use 'csv' o 'json'")
        
        logger.info(f"Contenido generado: {len(content)} bytes")
        
        # Retornar como descarga
        return StreamingResponse(
            io.BytesIO(content.encode('utf-8')),
            media_type=media_type,
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(content.encode('utf-8')))
            }
        )
    
    except Exception as e:
        logger.error(f"Error al exportar datos: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error al exportar datos: {str(e)}")


# ============================================
# ENDPOINTS - REPORTES AGREGADOS
# ============================================

@router.post("/reports/aggregated")
async def generate_aggregated_report(
    filters: Optional[ReportFilters] = None,
    db: Session = Depends(get_db)
) -> AggregatedReport:
    """
    UC-06: Generar reporte agregado con estadísticas de seguridad y rendimiento
    
    CRÍTICO: Proporciona métricas comparativas para análisis de seguridad
    """
    
    try:
        # Definir período de análisis
        if filters and filters.start_date:
            start = filters.start_date
        else:
            start = datetime.now() - timedelta(days=30)
        
        if filters and filters.end_date:
            end = filters.end_date
        else:
            end = datetime.now()
        
        # Consulta base con filtros de fecha
        base_query = db.query(AuditEvent).filter(
            AuditEvent.timestamp >= start,
            AuditEvent.timestamp <= end
        )
        
        # Aplicar otros filtros si existen
        if filters:
            if filters.event_types:
                base_query = base_query.filter(AuditEvent.event_type.in_(filters.event_types))
            if filters.user_ids:
                base_query = base_query.filter(AuditEvent.user_id.in_(filters.user_ids))
            if filters.ip_addresses:
                base_query = base_query.filter(AuditEvent.ip_address.in_(filters.ip_addresses))
        
        # Métricas básicas
        total_events = base_query.count()
        unique_users = db.query(func.count(func.distinct(AuditEvent.user_id))).filter(
            AuditEvent.timestamp >= start,
            AuditEvent.timestamp <= end
        ).scalar() or 0
        
        total_logins = base_query.filter(AuditEvent.event_type == 'login_success').count()
        failed_logins = base_query.filter(AuditEvent.event_type == 'login_failed').count()
        stepup_challenges = base_query.filter(AuditEvent.event_type == 'stepup_required').count()
        
        # Eventos de alto riesgo
        high_risk_query = db.query(func.count(RiskEvaluation.id)).filter(
            RiskEvaluation.evaluated_at >= start,
            RiskEvaluation.evaluated_at <= end,
            RiskEvaluation.risk_score >= 70
        )
        high_risk_events = high_risk_query.scalar() or 0
        
        # Score de riesgo promedio
        avg_risk = db.query(func.avg(RiskEvaluation.risk_score)).filter(
            RiskEvaluation.evaluated_at >= start,
            RiskEvaluation.evaluated_at <= end
        ).scalar() or 0
        
        # Desglose por tipo de evento
        event_breakdown = {}
        event_types = db.query(
            AuditEvent.event_type,
            func.count(AuditEvent.id)
        ).filter(
            AuditEvent.timestamp >= start,
            AuditEvent.timestamp <= end
        ).group_by(AuditEvent.event_type).all()
        
        for event_type, count in event_types:
            event_breakdown[event_type] = count
        
        # Top IPs
        top_ips_query = db.query(
            AuditEvent.ip_address,
            func.count(AuditEvent.id).label('count')
        ).filter(
            AuditEvent.timestamp >= start,
            AuditEvent.timestamp <= end,
            AuditEvent.ip_address.isnot(None)
        ).group_by(AuditEvent.ip_address).order_by(desc('count')).limit(10)
        
        top_ips = [
            {"ip": ip, "count": count}
            for ip, count in top_ips_query.all()
        ]
        
        # Distribución por hora
        hourly_dist = db.query(
            func.extract('hour', AuditEvent.timestamp).label('hour'),
            func.count(AuditEvent.id).label('count')
        ).filter(
            AuditEvent.timestamp >= start,
            AuditEvent.timestamp <= end
        ).group_by('hour').order_by('hour').all()
        
        hourly_distribution = [
            {"hour": int(hour), "count": count}
            for hour, count in hourly_dist
        ]
        
        return AggregatedReport(
            period=f"{start.isoformat()} - {end.isoformat()}",
            total_events=total_events,
            unique_users=unique_users,
            total_logins=total_logins,
            failed_logins=failed_logins,
            stepup_challenges=stepup_challenges,
            high_risk_events=high_risk_events,
            avg_risk_score=float(avg_risk) if avg_risk else 0.0,
            event_type_breakdown=event_breakdown,
            top_ips=top_ips,
            hourly_distribution=hourly_distribution
        )
    
    except Exception as e:
        logger.error(f"Error al generar reporte agregado: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error al generar reporte agregado: {str(e)}")


# ============================================
# ENDPOINTS - CONSULTAS CON FILTROS AVANZADOS
# ============================================

@router.post("/events/search")
async def search_audit_events(
    filters: ReportFilters,
    db: Session = Depends(get_db)
):
    """
    UC-06: Búsqueda avanzada de eventos de auditoría con filtros múltiples
    """
    
    try:
        # Construir consulta
        query = db.query(AuditEvent)
        query = apply_filters(query, filters)
        
        # Contar total primero
        count_query = db.query(func.count(AuditEvent.id))
        count_query = apply_filters(count_query, filters)
        total_count = count_query.scalar()
        
        # Aplicar paginación
        query = query.limit(filters.limit).offset(filters.offset)
        
        events = query.all()
        
        # Formatear resultados
        results = []
        for event in events:
            results.append({
                'id': str(event.id),
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'user_id': str(event.user_id) if event.user_id else None,
                'ip_address': event.ip_address,
                'user_agent': event.user_agent,
                'event_data': event.event_data
            })
        
        return {
            'total': total_count,
            'limit': filters.limit,
            'offset': filters.offset,
            'events': results
        }
    
    except Exception as e:
        logger.error(f"Error en búsqueda de eventos: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error en búsqueda de eventos: {str(e)}")


@router.get("/statistics/summary")
async def get_statistics_summary(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """
    UC-06: Obtener resumen estadístico rápido de los últimos N días
    """
    
    try:
        start_date = datetime.now() - timedelta(days=days)
        
        # Métricas básicas
        total_events = db.query(func.count(AuditEvent.id)).filter(
            AuditEvent.timestamp >= start_date
        ).scalar() or 0
        
        total_users = db.query(func.count(func.distinct(AuditEvent.user_id))).filter(
            AuditEvent.timestamp >= start_date
        ).scalar() or 0
        
        success_logins = db.query(func.count(AuditEvent.id)).filter(
            AuditEvent.timestamp >= start_date,
            AuditEvent.event_type == 'login_success'
        ).scalar() or 0
        
        failed_logins = db.query(func.count(AuditEvent.id)).filter(
            AuditEvent.timestamp >= start_date,
            AuditEvent.event_type == 'login_failed'
        ).scalar() or 0
        
        # Tasa de éxito
        success_rate = (success_logins / (success_logins + failed_logins) * 100) if (success_logins + failed_logins) > 0 else 0
        
        return {
            'period_days': days,
            'total_events': total_events,
            'active_users': total_users,
            'successful_logins': success_logins,
            'failed_logins': failed_logins,
            'success_rate': round(success_rate, 2),
            'generated_at': datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error al obtener estadísticas: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")


# ============================================
# ENDPOINTS - REPORTES DE CUMPLIMIENTO
# ============================================

@router.get("/compliance/access-log")
async def get_compliance_access_log(
    user_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """
    UC-06: Generar log de accesos para cumplimiento normativo
    """
    
    try:
        query = db.query(AuditEvent).filter(
            AuditEvent.event_type.in_(['login_success', 'access_granted', 'access_denied'])
        )
        
        if user_id:
            query = query.filter(AuditEvent.user_id == user_id)
        
        if start_date:
            query = query.filter(AuditEvent.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditEvent.timestamp <= end_date)
        
        query = query.order_by(desc(AuditEvent.timestamp)).limit(1000)
        
        events = query.all()
        
        access_log = []
        for event in events:
            access_log.append({
                'timestamp': event.timestamp.isoformat(),
                'user_id': str(event.user_id) if event.user_id else 'N/A',
                'action': event.event_type,
                'ip_address': event.ip_address,
                'result': 'success' if 'success' in event.event_type or 'granted' in event.event_type else 'denied',
                'details': event.event_data
            })
        
        return {
            'total_records': len(access_log),
            'access_log': access_log
        }
    
    except Exception as e:
        logger.error(f"Error al generar log de cumplimiento: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error al generar log de cumplimiento: {str(e)}")

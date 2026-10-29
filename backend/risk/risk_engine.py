from typing import Dict, Any, Optional
from datetime import datetime, time, timedelta
from sqlalchemy.orm import Session as DBSession
from models import User, Device, AuditEvent
import user_agents
from decimal import Decimal
import logging
import requests
import pytz

logger = logging.getLogger(__name__)

class RiskEngine:
    def __init__(self):
        self.weights = {
            'device': 0.30,
            'location': 0.25,
            'time': 0.20,
            'failed_attempts': 0.15,
            'velocity': 0.10
        }
        
        # Horario laboral: 8:00 AM a 7:00 PM (Buenos Aires)
        self.business_hours_start = time(8, 0)
        self.business_hours_end = time(19, 0)
        
        # Zona horaria de Buenos Aires
        self.timezone = pytz.timezone('America/Argentina/Buenos_Aires')
    
    def evaluate_risk(
        self,
        user: User,
        ip_address: str,
        user_agent: str,
        db: DBSession
    ) -> Dict[str, Any]:
        """Evalúa el riesgo contextual de un intento de autenticación."""
        
        logger.info(f"[RISK ENGINE] ===== INICIO EVALUACIÓN DE RIESGO =====")
        logger.info(f"[RISK ENGINE] Usuario: {user.email} (ID: {user.id})")
        logger.info(f"[RISK ENGINE] IP: {ip_address}")
        
        context = self._build_context(user, ip_address, user_agent, db)
        
        factors = {
            'device': self._evaluate_device_risk(context, db),
            'location': self._evaluate_location_risk(context, user, db),
            'time': self._evaluate_time_risk(context),
            'failed_attempts': self._evaluate_failed_attempts(user, db),
            'velocity': self._evaluate_velocity_risk(user, db)
        }
        
        # LOG: Mostrar scores de cada factor
        logger.info(f"[RISK ENGINE] --- SCORES POR FACTOR ---")
        for factor_name, factor_data in factors.items():
            weighted_score = factor_data['score'] * self.weights[factor_name]
            logger.info(f"[RISK ENGINE] {factor_name}: {factor_data['score']} pts (peso {self.weights[factor_name]}) = {weighted_score:.2f} pts ponderados")
            logger.info(f"[RISK ENGINE]   └─ {factor_data['message']}")
        
        total_score = sum(
            factors[factor]['score'] * self.weights[factor]
            for factor in factors
        )
        
        risk_level = self._calculate_risk_level(total_score)
        
        logger.info(f"[RISK ENGINE] --- RESULTADO FINAL ---")
        logger.info(f"[RISK ENGINE] Score Total: {total_score:.2f}/100")
        logger.info(f"[RISK ENGINE] Nivel de Riesgo: {risk_level.upper()}")
        logger.info(f"[RISK ENGINE] ===== FIN EVALUACIÓN =====")
        
        return {
            'score': Decimal(str(round(total_score, 2))),
            'level': risk_level,
            'factors': factors,
            'context': context
        }
    
    def _build_context(
        self,
        user: User,
        ip_address: str,
        user_agent: str,
        db: DBSession
    ) -> Dict[str, Any]:
        """Construye el contexto del intento de autenticación."""
        
        ua = user_agents.parse(user_agent)
        
        location = self._get_location_from_ip(ip_address)
        
        # ✅ Usar hora de Buenos Aires en lugar de UTC
        utc_now = datetime.now(pytz.utc)
        current_time = utc_now.astimezone(self.timezone)
        
        # ✅ Calcular si es horario laboral (Buenos Aires)
        is_business_hours = (
            self.business_hours_start <= current_time.time() <= self.business_hours_end
            and current_time.weekday() < 5  # Lunes a Viernes
        )
        
        logger.info(f"[RISK ENGINE] Hora UTC: {utc_now.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"[RISK ENGINE] Hora Buenos Aires: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"[RISK ENGINE] Es horario laboral: {is_business_hours}")
        
        return {
            'user_id': user.id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'browser': ua.browser.family,
            'os': ua.os.family,
            'device_type': 'mobile' if ua.is_mobile else 'desktop',
            'location': location,
            'timestamp': current_time,
            'is_business_hours': is_business_hours  # ✅ NUEVO: agregado al contexto
        }
    
    def _evaluate_device_risk(
        self,
        context: Dict,
        db: DBSession
    ) -> Dict[str, Any]:
        """Evalúa el riesgo basado en el dispositivo."""
        
        # Generar fingerprint usando user_agent en lugar de ip_address
        device_fingerprint = f"{context['browser']}_{context['os']}_{context['user_agent'][:50]}"
        
        # LOG DE DEBUG: Ver qué fingerprint está buscando
        logger.info(f"[RISK ENGINE] Buscando device_fingerprint: {device_fingerprint}")
        
        known_device = db.query(Device).filter(
            Device.device_fingerprint == device_fingerprint
        ).first()
        
        if known_device:
            logger.info(f"[RISK ENGINE] ✅ Dispositivo encontrado: {known_device.device_name}")
            return {
                'score': 0,
                'known': True,
                'message': f"Dispositivo conocido: {known_device.device_name}"
            }
        else:
            logger.info(f"[RISK ENGINE] ❌ Dispositivo NO encontrado en BD")
            return {
                'score': 40,
                'known': False,
                'message': "Dispositivo desconocido - primera vez"
            }
    
    def _evaluate_location_risk(
        self,
        context: Dict,
        user: User,
        db: DBSession
    ) -> Dict[str, Any]:
        """Evalúa el riesgo basado en la ubicación geográfica."""
        
        logger.info(f"[RISK ENGINE] Evaluando riesgo de ubicación...")
        
        current_location = context.get('location', {})
        current_country = current_location.get('country', 'Unknown')
        current_country_name = current_location.get('country_name', 'Unknown')
        current_display = current_location.get('display', 'Unknown')
        current_ip = context.get('ip_address', 'Unknown')
        
        logger.info(f"[RISK ENGINE] Ubicación actual: {current_display} (País: {current_country})")
        
        # ✅ NUEVO: Países confiables (bajo riesgo automático)
        trusted_countries = ['AR']  # Argentina
        
        if current_country in trusted_countries:
            logger.info(f"[RISK ENGINE] ✅ País CONFIABLE: {current_country}")
            return {
                'score': 5,  # Riesgo muy bajo
                'known': True,
                'country': current_country,
                'message': f"{current_display} (IP: {current_ip}, {current_country_name})"
            }
        
        # Obtener ubicaciones conocidas del usuario
        recent_locations = db.query(Device.last_seen_location).filter(
            Device.user_id == user.id,
            Device.last_seen_location != None
        ).distinct().all()
        
        recent_locations = [loc[0] for loc in recent_locations if loc[0]]
        
        logger.info(f"[RISK ENGINE] Ubicaciones conocidas del usuario ({len(recent_locations)}): {recent_locations}")
        
        # Primera vez - sin ubicaciones previas
        if not recent_locations:
            logger.info(f"[RISK ENGINE] ⚠️ No hay ubicaciones conocidas - Primera vez")
            return {
                'score': 20,
                'known': False,
                'country': current_country,
                'message': f"Primera ubicación: {current_display} (IP: {current_ip}, {current_country_name})"
            }
        
        # Verificar si la ubicación actual está en el historial
        if current_display in recent_locations:
            logger.info(f"[RISK ENGINE] ✅ Ubicación CONOCIDA: {current_display}")
            return {
                'score': 0,
                'known': True,
                'country': current_country,
                'message': f"Ubicación conocida: {current_display} (IP: {current_ip}, {current_country_name})"
            }
        else:
            logger.info(f"[RISK ENGINE] ❌ Ubicación NUEVA: {current_display}")
            logger.info(f"[RISK ENGINE] No coincide con ninguna de: {recent_locations}")
            return {
                'score': 35,
                'known': False,
                'country': current_country,
                'message': f"Nueva ubicación: {current_display} (IP: {current_ip}, {current_country_name})"
            }
    
    def _evaluate_time_risk(self, context: Dict) -> Dict[str, Any]:
        """Evalúa el riesgo basado en el horario de acceso."""
        
        current_time = context['timestamp'].time()
        
        is_business_hours = (
            self.business_hours_start <= current_time <= self.business_hours_end
        )
        
        is_weekday = context['timestamp'].weekday() < 5
        
        if is_business_hours and is_weekday:
            return {
                'score': 0,
                'is_business_hours': True,
                'message': "Horario laboral (Lun-Vie 8-19hs)"
            }
        elif is_weekday:
            return {
                'score': 200,  # 200 × 0.20 = 40 pts → MEDIUM (40-74)
                'is_business_hours': False,
                'message': "Fuera de horario laboral"
            }
        else:
            return {
                'score': 300,  # 300 × 0.20 = 60 pts → MEDIUM (40-74)
                'is_business_hours': False,
                'message': "Acceso en fin de semana"
            }
    
    def _evaluate_failed_attempts(
        self,
        user: User,
        db: DBSession
    ) -> Dict[str, Any]:
        """Evalúa intentos fallidos recientes."""
        
        # Usar hora actual de Buenos Aires
        utc_now = datetime.now(pytz.utc)
        current_time_ba = utc_now.astimezone(self.timezone)
        one_hour_ago = current_time_ba - timedelta(hours=1)
        
        recent_failures = db.query(AuditEvent).filter(
            AuditEvent.user_id == user.id,
            AuditEvent.event_type == 'auth_failed',
            AuditEvent.timestamp >= one_hour_ago.replace(tzinfo=None)  # Comparar sin timezone
        ).count()
        
        if recent_failures == 0:
            score = 0
            message = "Sin intentos fallidos recientes"
        elif recent_failures <= 2:
            score = 20
            message = f"{recent_failures} intentos fallidos en la última hora"
        else:
            score = 50
            message = f"ALERTA: {recent_failures} intentos fallidos recientes"
        
        return {
            'score': score,
            'count': recent_failures,
            'message': message
        }
    
    def _evaluate_velocity_risk(
        self,
        user: User,
        db: DBSession
    ) -> Dict[str, Any]:
        """Evalúa la velocidad de intentos de autenticación."""
        
        # Usar hora actual de Buenos Aires
        utc_now = datetime.now(pytz.utc)
        current_time_ba = utc_now.astimezone(self.timezone)
        five_minutes_ago = current_time_ba - timedelta(minutes=5)
        
        recent_attempts = db.query(AuditEvent).filter(
            AuditEvent.user_id == user.id,
            AuditEvent.event_type.in_(['auth_success', 'auth_failed']),
            AuditEvent.timestamp >= five_minutes_ago.replace(tzinfo=None)  # Comparar sin timezone
        ).count()
        
        if recent_attempts <= 2:
            return {
                'score': 0,
                'attempts': recent_attempts,
                'message': "Velocidad normal de autenticación"
            }
        elif recent_attempts <= 5:
            return {
                'score': 25,
                'attempts': recent_attempts,
                'message': f"Velocidad elevada: {recent_attempts} intentos en 5 min"
            }
        else:
            return {
                'score': 50,
                'attempts': recent_attempts,
                'message': f"ALERTA: Posible ataque - {recent_attempts} intentos en 5 min"
            }
    
    def _calculate_risk_level(self, score: float) -> str:
        """Calcula el nivel de riesgo según el score."""
        
        if score < 40:
            return 'low'
        elif score < 75:
            return 'medium'
        else:
            return 'high'
    
    def _get_location_from_ip(self, ip_address: str) -> Dict[str, str]:
        """Obtiene la ubicación aproximada desde la IP usando API de geolocalización."""
        
        # IPs locales
        if ip_address.startswith('127.') or ip_address == 'localhost':
            return {
                'country': 'AR',  # Argentina por defecto en desarrollo
                'country_name': 'Argentina',
                'city': 'Buenos Aires',
                'display': 'Localhost (Desarrollo)'
            }
        
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return {
                'country': 'AR',  # Argentina por defecto en red local
                'country_name': 'Argentina',
                'city': 'Red Local',
                'display': 'Red Local'
            }
        
        # Geolocalización real usando API gratuita
        try:
            # Usar ipapi.co (gratuito, 1000 req/día, no requiere API key)
            response = requests.get(
                f'https://ipapi.co/{ip_address}/json/',
                timeout=2
            )
            
            if response.status_code == 200:
                data = response.json()
                
                country = data.get('country_code', 'Unknown')
                country_name = data.get('country_name', 'Unknown')
                city = data.get('city', 'Unknown')
                
                logger.info(f"[GEOLOCATION] IP: {ip_address} → {city}, {country_name} ({country})")
                
                return {
                    'country': country,
                    'country_name': country_name,
                    'city': city,
                    'display': f"{city}, {country_name}"
                }
            else:
                logger.warning(f"[GEOLOCATION] API error: {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning(f"[GEOLOCATION] Timeout para IP {ip_address}")
        except Exception as e:
            logger.error(f"[GEOLOCATION] Error: {e}")
        
        # Fallback si la API falla
        return {
            'country': 'Unknown',
            'country_name': 'Unknown',
            'city': 'Unknown',
            'display': f"IP: {ip_address}"
        }

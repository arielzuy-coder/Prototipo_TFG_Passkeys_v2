from typing import Dict, Any, List
from sqlalchemy.orm import Session as DBSession
from models import User, Policy
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

class PolicyEngine:
    def __init__(self):
        self.default_policies = [
            {
                'name': 'high_risk_deny',
                'description': 'Denegar acceso si el riesgo es alto',
                'conditions': {'min_risk_score': 75},
                'action': 'deny',
                'priority': 1
            },
            {
                'name': 'medium_risk_stepup',
                'description': 'Requerir autenticación adicional para riesgo medio',
                'conditions': {'min_risk_score': 40, 'max_risk_score': 74},
                'action': 'stepup',
                'priority': 2
            },
            {
                'name': 'low_risk_allow',
                'description': 'Permitir acceso si el riesgo es bajo',
                'conditions': {'max_risk_score': 39},
                'action': 'allow',
                'priority': 3
           }
        ]
    
    def evaluate_policies(
        self,
        user: User,
        risk_score: Decimal,
        context: Dict[str, Any],
        db: DBSession
    ) -> Dict[str, Any]:
        """Evalúa las políticas aplicables y retorna la acción a tomar."""
        
        logger.info(f"[POLICY ENGINE] ===== EVALUANDO POLÍTICAS =====")
        logger.info(f"[POLICY ENGINE] Usuario: {user.email}")
        logger.info(f"[POLICY ENGINE] Risk Score: {risk_score}")
        
        policies = db.query(Policy).filter(
            Policy.enabled == True
        ).order_by(Policy.priority.asc()).all()
        
        logger.info(f"[POLICY ENGINE] Total de políticas activas: {len(policies)}")
        
        if not policies:
            logger.info(f"[POLICY ENGINE] No hay políticas, creando políticas por defecto...")
            policies = self._create_default_policies(db)
        
        risk_score_float = float(risk_score)
        
        for policy in policies:
            logger.info(f"[POLICY ENGINE] --- Evaluando Política ---")
            logger.info(f"[POLICY ENGINE] Nombre: {policy.name}")
            logger.info(f"[POLICY ENGINE] Prioridad: {policy.priority}")
            logger.info(f"[POLICY ENGINE] Condiciones: {policy.conditions}")
            logger.info(f"[POLICY ENGINE] Acción: {policy.action}")
            
            if self._policy_matches(policy, risk_score_float, context):
                logger.info(f"[POLICY ENGINE] ✅ MATCH! Aplicando política: {policy.name}")
                logger.info(f"[POLICY ENGINE] Acción decidida: {policy.action}")
                logger.info(f"[POLICY ENGINE] ===== FIN EVALUACIÓN POLÍTICAS =====")
                return {
                    'action': policy.action,
                    'policy_name': policy.name,
                    'policy_description': policy.description,
                    'matched': True
                }
            else:
                logger.info(f"[POLICY ENGINE] ❌ NO MATCH - Continuando con siguiente política...")
        
        logger.info(f"[POLICY ENGINE] ⚠️ Ninguna política matcheó - Usando política por defecto (allow)")
        logger.info(f"[POLICY ENGINE] ===== FIN EVALUACIÓN POLÍTICAS =====")
        return {
            'action': 'allow',
            'policy_name': 'default',
            'policy_description': 'Política por defecto',
            'matched': False
        }
    
    def _policy_matches(
        self,
        policy: Policy,
        risk_score: float,
        context: Dict[str, Any]
    ) -> bool:
        """Verifica si una política coincide con el contexto actual."""
        
        conditions = policy.conditions
        
        logger.info(f"[POLICY ENGINE]   Verificando condición min_risk_score...")
        if 'min_risk_score' in conditions:
            min_score = conditions['min_risk_score']
            if risk_score < min_score:
                logger.info(f"[POLICY ENGINE]   ❌ Score {risk_score} < {min_score} - NO cumple")
                return False
            logger.info(f"[POLICY ENGINE]   ✅ Score {risk_score} >= {min_score} - Cumple")
        
        logger.info(f"[POLICY ENGINE]   Verificando condición max_risk_score...")
        if 'max_risk_score' in conditions:
            max_score = conditions['max_risk_score']
            if risk_score > max_score:
                logger.info(f"[POLICY ENGINE]   ❌ Score {risk_score} > {max_score} - NO cumple")
                return False
            logger.info(f"[POLICY ENGINE]   ✅ Score {risk_score} <= {max_score} - Cumple")
        
        # ✅ CORRECCIÓN: allowed_countries con lógica diferenciada
        if 'allowed_countries' in conditions:
            allowed = conditions['allowed_countries']
            location = context.get('location', {})
            current_country = location.get('country', 'Unknown')
            logger.info(f"[POLICY ENGINE]   Verificando país: {current_country} | Lista permitida: {allowed}")
            
            is_allowed_country = current_country in allowed
            
            # Si la acción es 'allow', solo aplica si el país está permitido
            if policy.action == 'allow':
                if not is_allowed_country:
                    logger.info(f"[POLICY ENGINE]   ❌ País {current_country} no permitido para acción 'allow' - NO cumple")
                    return False
                logger.info(f"[POLICY ENGINE]   ✅ País {current_country} permitido para acción 'allow' - Cumple")
            # Si la acción es 'stepup' o 'deny', solo aplica si el país NO está permitido
            else:
                if is_allowed_country:
                    logger.info(f"[POLICY ENGINE]   ✅ País {current_country} en lista permitida - política NO aplica (skip)")
                    return False
                logger.info(f"[POLICY ENGINE]   ❌ País {current_country} NO en lista permitida - política APLICA (stepup/deny)")
        
        # CONDICIÓN: blocked_countries
        if 'blocked_countries' in conditions:
            blocked = conditions['blocked_countries']
            location = context.get('location', {})
            current_country = location.get('country', 'Unknown')
            logger.info(f"[POLICY ENGINE]   Verificando país bloqueado: {current_country} en {blocked}")
            if current_country in blocked:
                logger.info(f"[POLICY ENGINE]   ❌ País {current_country} está bloqueado - NO cumple")
                return False
            logger.info(f"[POLICY ENGINE]   ✅ País {current_country} no bloqueado - Cumple")
        
        if 'required_location' in conditions:
            required = conditions['required_location']
            actual = context.get('location')
            logger.info(f"[POLICY ENGINE]   Verificando ubicación requerida: {required} vs actual: {actual}")
            if actual != required:
                logger.info(f"[POLICY ENGINE]   ❌ Ubicación no coincide - NO cumple")
                return False
            logger.info(f"[POLICY ENGINE]   ✅ Ubicación coincide - Cumple")
        
        if 'allowed_devices' in conditions:
            allowed = conditions['allowed_devices']
            device = context.get('device_type')
            logger.info(f"[POLICY ENGINE]   Verificando dispositivo permitido: {device} en {allowed}")
            if device not in allowed:
                logger.info(f"[POLICY ENGINE]   ❌ Dispositivo no permitido - NO cumple")
                return False
            logger.info(f"[POLICY ENGINE]   ✅ Dispositivo permitido - Cumple")
        
        # ✅ CORRECCIÓN: business_hours_only con lógica diferenciada
        if 'business_hours_only' in conditions and conditions['business_hours_only']:
            is_business_hours = context.get('is_business_hours', False)
            logger.info(f"[POLICY ENGINE]   Verificando horario laboral: {is_business_hours}")
            
            # Si la acción es 'allow', solo aplica durante horario laboral
            if policy.action == 'allow':
                if not is_business_hours:
                    logger.info(f"[POLICY ENGINE]   ❌ Fuera de horario laboral - política 'allow' NO aplica")
                    return False
                logger.info(f"[POLICY ENGINE]   ✅ En horario laboral - política 'allow' aplica")
            # Si la acción es 'stepup' o 'deny', solo aplica fuera de horario laboral
            else:
                if is_business_hours:
                    logger.info(f"[POLICY ENGINE]   ✅ En horario laboral - política stepup/deny NO aplica (skip)")
                    return False
                logger.info(f"[POLICY ENGINE]   ❌ Fuera de horario laboral - política APLICA (stepup/deny)")
        
        logger.info(f"[POLICY ENGINE]   ✅ TODAS las condiciones cumplen - MATCH!")
        return True
    
    def _create_default_policies(self, db: DBSession) -> List[Policy]:
        """Crea políticas por defecto en la base de datos."""
        
        policies = []
        
        for policy_data in self.default_policies:
            policy = Policy(
                name=policy_data['name'],
                description=policy_data['description'],
                conditions=policy_data['conditions'],
                action=policy_data['action'],
                priority=policy_data['priority'],
                enabled=True
            )
            db.add(policy)
            policies.append(policy)
        
        db.commit()
        
        return policies
    
    def create_custom_policy(
        self,
        name: str,
        description: str,
        conditions: Dict[str, Any],
        action: str,
        priority: int,
        db: DBSession
    ) -> Policy:
        """Crea una política personalizada."""
        
        policy = Policy(
            name=name,
            description=description,
            conditions=conditions,
            action=action,
            priority=priority,
            enabled=True
        )
        
        db.add(policy)
        db.commit()
        db.refresh(policy)
        
        return policy
    
    def update_policy(
        self,
        policy_id: str,
        updates: Dict[str, Any],
        db: DBSession
    ) -> Policy:
        """Actualiza una política existente."""
        
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        
        if not policy:
            raise ValueError(f"Política {policy_id} no encontrada")
        
        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        db.commit()
        db.refresh(policy)
        
        return policy
    
    def delete_policy(self, policy_id: str, db: DBSession) -> bool:
        """Elimina una política."""
        
        policy = db.query(Policy).filter(Policy.id == policy_id).first()
        
        if not policy:
            return False
        
        db.delete(policy)
        db.commit()
        
        return True

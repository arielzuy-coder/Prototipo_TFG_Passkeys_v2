"""
Script para agregar políticas de Step-Up basadas en geolocalización y horario.

Este script crea políticas específicas que requieren autenticación adicional
cuando el usuario intenta acceder:
1. Desde fuera de Argentina
2. Fuera del horario laboral (8am-6pm, Lun-Vie)

Estas políticas tienen MAYOR PRIORIDAD que las políticas basadas en score de riesgo.
"""

import sys
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Agregar el directorio backend al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from models import Base, Policy
from config import settings

def create_stepup_policies():
    """Crea políticas específicas para step-up authentication."""
    
    # Conectar a la base de datos
    engine = create_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        print("\n" + "="*70)
        print("CONFIGURACIÓN DE POLÍTICAS DE STEP-UP")
        print("="*70 + "\n")
        
        # 1. Eliminar políticas existentes de geolocalización/horario si existen
        print("🗑️  Eliminando políticas antiguas de geolocalización y horario...")
        db.query(Policy).filter(Policy.name.in_([
            'foreign_country_stepup',
            'outside_business_hours_stepup'
        ])).delete(synchronize_session=False)
        db.commit()
        print("✅ Políticas antiguas eliminadas\n")
        
        # 2. Reordenar prioridades de políticas existentes
        print("🔄 Reordenando prioridades de políticas existentes...")
        
        # Las políticas por score ahora tendrán prioridad 10, 11, 12
        high_risk = db.query(Policy).filter(Policy.name == 'high_risk_deny').first()
        if high_risk:
            high_risk.priority = 10
            print(f"   • high_risk_deny → prioridad 10")
        
        medium_risk = db.query(Policy).filter(Policy.name == 'medium_risk_stepup').first()
        if medium_risk:
            medium_risk.priority = 11
            print(f"   • medium_risk_stepup → prioridad 11")
        
        low_risk = db.query(Policy).filter(Policy.name == 'low_risk_allow').first()
        if low_risk:
            low_risk.priority = 12
            print(f"   • low_risk_allow → prioridad 12")
        
        db.commit()
        print("✅ Prioridades actualizadas\n")
        
        # 3. Crear política: Acceso desde país extranjero requiere step-up
        print("🌍 Creando política de geolocalización...")
        foreign_country_policy = Policy(
            name='foreign_country_stepup',
            description='Requiere autenticación adicional para accesos desde fuera de Argentina',
            conditions={
                'allowed_countries': ['AR']  # Solo Argentina está permitida sin step-up
            },
            action='stepup',
            priority=1,  # MÁXIMA PRIORIDAD - se evalúa primero
            enabled=True
        )
        db.add(foreign_country_policy)
        print("   ✅ Política 'foreign_country_stepup' creada")
        print(f"      • Prioridad: 1 (se evalúa primero)")
        print(f"      • Condición: país debe ser Argentina (AR)")
        print(f"      • Acción: Step-Up si país != AR\n")
        
        # 4. Crear política: Acceso fuera de horario laboral requiere step-up
        print("🕐 Creando política de horario laboral...")
        business_hours_policy = Policy(
            name='outside_business_hours_stepup',
            description='Requiere autenticación adicional fuera del horario laboral (Lun-Vie 8am-6pm)',
            conditions={
                'business_hours_only': True  # Requiere que sea horario laboral
            },
            action='stepup',
            priority=2,  # Segunda prioridad
            enabled=True
        )
        db.add(business_hours_policy)
        print("   ✅ Política 'outside_business_hours_stepup' creada")
        print(f"      • Prioridad: 2 (se evalúa segunda)")
        print(f"      • Condición: horario 8am-6pm Lun-Vie")
        print(f"      • Acción: Step-Up si fuera de horario\n")
        
        db.commit()
        
        # 5. Verificar políticas creadas
        print("="*70)
        print("RESUMEN DE POLÍTICAS ACTIVAS")
        print("="*70 + "\n")
        
        all_policies = db.query(Policy).filter(Policy.enabled == True).order_by(Policy.priority.asc()).all()
        
        print(f"Total de políticas activas: {len(all_policies)}\n")
        
        for i, policy in enumerate(all_policies, 1):
            print(f"{i}. {policy.name}")
            print(f"   • Prioridad: {policy.priority}")
            print(f"   • Descripción: {policy.description}")
            print(f"   • Condiciones: {policy.conditions}")
            print(f"   • Acción: {policy.action.upper()}")
            print(f"   • Estado: {'✅ ACTIVA' if policy.enabled else '❌ DESACTIVADA'}")
            print()
        
        print("="*70)
        print("FLUJO DE EVALUACIÓN DE POLÍTICAS")
        print("="*70 + "\n")
        print("Cuando un usuario intenta acceder, las políticas se evalúan en este orden:\n")
        print("1️⃣  foreign_country_stepup (prioridad 1)")
        print("    → Si país != Argentina → Step-Up requerido\n")
        print("2️⃣  outside_business_hours_stepup (prioridad 2)")
        print("    → Si fuera de horario laboral → Step-Up requerido\n")
        print("3️⃣  high_risk_deny (prioridad 10)")
        print("    → Si risk_score ≥ 75 → Acceso denegado\n")
        print("4️⃣  medium_risk_stepup (prioridad 11)")
        print("    → Si 40 ≤ risk_score < 75 → Step-Up requerido\n")
        print("5️⃣  low_risk_allow (prioridad 12)")
        print("    → Si risk_score < 40 → Acceso permitido\n")
        
        print("="*70)
        print("✅ CONFIGURACIÓN COMPLETADA EXITOSAMENTE")
        print("="*70 + "\n")
        
        print("📋 PRÓXIMOS PASOS:")
        print("   1. Las nuevas políticas ya están activas en la base de datos")
        print("   2. Puedes verlas en el Panel de Administración")
        print("   3. Prueba acceder desde otra ubicación o fuera de horario")
        print("   4. El sistema debería solicitar step-up authentication\n")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        db.rollback()
        return False
        
    finally:
        db.close()

if __name__ == "__main__":
    print("\n🚀 Iniciando configuración de políticas de Step-Up...\n")
    success = create_stepup_policies()
    
    if success:
        print("✅ Script ejecutado exitosamente\n")
        sys.exit(0)
    else:
        print("❌ Hubo errores durante la ejecución\n")
        sys.exit(1)

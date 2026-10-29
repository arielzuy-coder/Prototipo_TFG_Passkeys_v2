"""
Script de Validación Post-Implementación
=========================================

Este script verifica que las correcciones de políticas de step-up
se implementaron correctamente y están funcionando.

Uso:
    python validate_policies.py
"""

import sys
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime, time
from decimal import Decimal

# Agregar el directorio backend al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from models import Policy
from config import settings
from risk.risk_engine import RiskEngine
from risk.policies import PolicyEngine

class Colors:
    """Colores ANSI para output en consola"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    """Imprime un header formateado"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

def print_success(text):
    """Imprime mensaje de éxito"""
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_warning(text):
    """Imprime mensaje de advertencia"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_error(text):
    """Imprime mensaje de error"""
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_info(text):
    """Imprime mensaje informativo"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")

def validate_database_policies():
    """Valida que las políticas estén correctamente configuradas en la BD."""
    
    print_header("VALIDACIÓN DE POLÍTICAS EN BASE DE DATOS")
    
    engine = create_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        policies = db.query(Policy).filter(Policy.enabled == True).order_by(Policy.priority.asc()).all()
        
        if not policies:
            print_error("No se encontraron políticas en la base de datos")
            return False
        
        print_info(f"Total de políticas activas: {len(policies)}")
        
        expected_policies = {
            'foreign_country_stepup': {'priority': 1, 'action': 'stepup'},
            'outside_business_hours_stepup': {'priority': 2, 'action': 'stepup'},
            'high_risk_deny': {'priority': 10, 'action': 'deny'},
            'medium_risk_stepup': {'priority': 11, 'action': 'stepup'},
            'low_risk_allow': {'priority': 12, 'action': 'allow'}
        }
        
        found_policies = {}
        errors = []
        
        print("\n📋 Políticas encontradas:\n")
        for i, policy in enumerate(policies, 1):
            print(f"{i}. {policy.name}")
            print(f"   Prioridad: {policy.priority}")
            print(f"   Acción: {policy.action}")
            print(f"   Condiciones: {policy.conditions}")
            print(f"   Estado: {'✅ Activa' if policy.enabled else '❌ Inactiva'}")
            print()
            
            found_policies[policy.name] = {
                'priority': policy.priority,
                'action': policy.action
            }
        
        # Verificar que existan las políticas esperadas
        print("\n🔍 Verificando políticas requeridas:\n")
        
        for name, expected in expected_policies.items():
            if name in found_policies:
                found = found_policies[name]
                if found['priority'] == expected['priority'] and found['action'] == expected['action']:
                    print_success(f"{name}: Correcta (prioridad {found['priority']}, acción {found['action']})")
                else:
                    print_warning(f"{name}: Encontrada pero con valores incorrectos")
                    if found['priority'] != expected['priority']:
                        errors.append(f"  • Prioridad incorrecta: esperada {expected['priority']}, encontrada {found['priority']}")
                    if found['action'] != expected['action']:
                        errors.append(f"  • Acción incorrecta: esperada {expected['action']}, encontrada {found['action']}")
            else:
                print_error(f"{name}: NO ENCONTRADA")
                errors.append(f"Falta política: {name}")
        
        if errors:
            print("\n❌ ERRORES DETECTADOS:")
            for error in errors:
                print(f"   {error}")
            return False
        else:
            print_success("\nTodas las políticas están correctamente configuradas")
            return True
            
    except Exception as e:
        print_error(f"Error al validar políticas: {e}")
        return False
    finally:
        db.close()

def validate_context_building():
    """Valida que el contexto se construya con is_business_hours."""
    
    print_header("VALIDACIÓN DE CONSTRUCCIÓN DE CONTEXTO")
    
    try:
        from models import User
        
        # Mock user
        class MockUser:
            id = "test-user-id"
            email = "test@example.com"
        
        user = MockUser()
        risk_engine = RiskEngine()
        
        # Construir contexto
        context = risk_engine._build_context(
            user=user,
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            db=None
        )
        
        print("📦 Contexto generado:\n")
        for key, value in context.items():
            print(f"   {key}: {value}")
        
        # Verificar que exista is_business_hours
        if 'is_business_hours' in context:
            print_success("\nCampo 'is_business_hours' presente en el contexto")
            print_info(f"Valor: {context['is_business_hours']}")
            
            # Verificar que sea un booleano
            if isinstance(context['is_business_hours'], bool):
                print_success("Tipo de dato correcto (bool)")
                return True
            else:
                print_error(f"Tipo de dato incorrecto: {type(context['is_business_hours'])}")
                return False
        else:
            print_error("Campo 'is_business_hours' NO encontrado en el contexto")
            print_warning("El archivo risk_engine.py no fue actualizado correctamente")
            return False
            
    except Exception as e:
        print_error(f"Error al validar contexto: {e}")
        import traceback
        traceback.print_exc()
        return False

def simulate_policy_evaluation():
    """Simula evaluaciones de políticas para diferentes escenarios."""
    
    print_header("SIMULACIÓN DE EVALUACIÓN DE POLÍTICAS")
    
    try:
        engine = create_engine(settings.DATABASE_URL)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        policy_engine = PolicyEngine()
        
        # Mock user
        class MockUser:
            id = "test-user-id"
            email = "test@example.com"
        
        user = MockUser()
        
        # Escenarios de prueba
        scenarios = [
            {
                'name': 'Acceso desde Argentina en horario laboral',
                'risk_score': Decimal('25.0'),
                'context': {
                    'location': {
                        'country': 'AR',
                        'city': 'Buenos Aires',
                        'display': 'Buenos Aires, Argentina'
                    },
                    'is_business_hours': True
                },
                'expected_action': 'allow'
            },
            {
                'name': 'Acceso desde USA en horario laboral',
                'risk_score': Decimal('30.0'),
                'context': {
                    'location': {
                        'country': 'US',
                        'city': 'New York',
                        'display': 'New York, United States'
                    },
                    'is_business_hours': True
                },
                'expected_action': 'stepup'
            },
            {
                'name': 'Acceso desde Argentina fuera de horario',
                'risk_score': Decimal('25.0'),
                'context': {
                    'location': {
                        'country': 'AR',
                        'city': 'Buenos Aires',
                        'display': 'Buenos Aires, Argentina'
                    },
                    'is_business_hours': False
                },
                'expected_action': 'stepup'
            },
            {
                'name': 'Acceso de alto riesgo desde Argentina',
                'risk_score': Decimal('85.0'),
                'context': {
                    'location': {
                        'country': 'AR',
                        'city': 'Buenos Aires',
                        'display': 'Buenos Aires, Argentina'
                    },
                    'is_business_hours': True
                },
                'expected_action': 'deny'
            }
        ]
        
        all_passed = True
        
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n{'─'*70}")
            print(f"Escenario {i}: {scenario['name']}")
            print(f"{'─'*70}")
            print(f"Risk Score: {scenario['risk_score']}")
            print(f"País: {scenario['context']['location']['country']}")
            print(f"Horario laboral: {scenario['context']['is_business_hours']}")
            print(f"Acción esperada: {scenario['expected_action'].upper()}")
            
            # Evaluar política
            result = policy_engine.evaluate_policies(
                user=user,
                risk_score=scenario['risk_score'],
                context=scenario['context'],
                db=db
            )
            
            print(f"\nResultado obtenido:")
            print(f"  • Acción: {result['action'].upper()}")
            print(f"  • Política: {result['policy_name']}")
            print(f"  • Descripción: {result['policy_description']}")
            
            if result['action'] == scenario['expected_action']:
                print_success(f"✓ Escenario {i} PASÓ")
            else:
                print_error(f"✗ Escenario {i} FALLÓ")
                print(f"  Esperado: {scenario['expected_action']}")
                print(f"  Obtenido: {result['action']}")
                all_passed = False
        
        db.close()
        
        print(f"\n{'='*70}\n")
        if all_passed:
            print_success("Todos los escenarios pasaron correctamente")
            return True
        else:
            print_error("Algunos escenarios fallaron")
            return False
            
    except Exception as e:
        print_error(f"Error en simulación: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Función principal de validación."""
    
    print(f"\n{Colors.BOLD}{'='*70}")
    print(f"VALIDACIÓN DE POLÍTICAS DE STEP-UP")
    print(f"{'='*70}{Colors.END}\n")
    
    results = {
        'database': False,
        'context': False,
        'simulation': False
    }
    
    # Test 1: Políticas en base de datos
    results['database'] = validate_database_policies()
    
    # Test 2: Contexto con is_business_hours
    results['context'] = validate_context_building()
    
    # Test 3: Simulación de evaluaciones
    results['simulation'] = simulate_policy_evaluation()
    
    # Resumen final
    print_header("RESUMEN DE VALIDACIÓN")
    
    total_tests = len(results)
    passed_tests = sum(results.values())
    
    print(f"Tests ejecutados: {total_tests}")
    print(f"Tests exitosos: {passed_tests}")
    print(f"Tests fallidos: {total_tests - passed_tests}\n")
    
    for test_name, passed in results.items():
        status = "✅ PASÓ" if passed else "❌ FALLÓ"
        print(f"  {test_name.upper()}: {status}")
    
    print()
    
    if all(results.values()):
        print_success("🎉 ¡TODAS LAS VALIDACIONES PASARON!")
        print_info("Las políticas de step-up están correctamente implementadas")
        return 0
    else:
        print_error("⚠️  ALGUNAS VALIDACIONES FALLARON")
        print_warning("Revisa los errores anteriores y verifica:")
        print("  1. Que los archivos se reemplazaron correctamente")
        print("  2. Que el script fix_stepup_policies.py se ejecutó")
        print("  3. Que el servidor se reinició después de los cambios")
        return 1

if __name__ == "__main__":
    sys.exit(main())

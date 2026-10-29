import psycopg2
import sys

# Conexión a Render
DATABASE_URL = "postgresql://authuser:AFbQjZswfUuYqFHwRK5d3nO1yllu1nw5@dpg-d40ijieuk2gs73a51fs0-a.oregon-postgres.render.com/auth_passkeys"

print("🔌 Conectando a PostgreSQL...")

try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    
    print("✅ Conectado!\n")
    
    # Ver políticas actuales
    print("📊 Políticas ACTUALES:")
    print("-" * 80)
    cur.execute("""
        SELECT name, 
               conditions->>'min_risk_score' as min_score,
               conditions->>'max_risk_score' as max_score,
               action
        FROM policies
        ORDER BY priority;
    """)
    
    for row in cur.fetchall():
        print(f"  {row[0]:20} | min:{row[1]:4} | max:{row[2]:4} | {row[3]}")
    
    print("\n⚠️  ¿El medium_risk_stepup tiene min_score diferente de 40?")
    print("    Si es así, vamos a corregirlo...\n")
    
    # Corregir políticas
    print("🔧 Eliminando políticas incorrectas...")
    cur.execute("DELETE FROM policies;")
    
    print("✨ Insertando políticas correctas...")
    cur.execute("""
        INSERT INTO policies (name, description, conditions, action, priority, enabled, created_at, updated_at)
        VALUES 
        ('high_risk_deny', 'Denegar acceso si el riesgo es alto', 
         '{"min_risk_score": 75}', 'deny', 1, true, NOW(), NOW()),
        
        ('medium_risk_stepup', 'Requerir autenticación adicional para riesgo medio',
         '{"min_risk_score": 40, "max_risk_score": 74}', 'stepup', 2, true, NOW(), NOW()),
        
        ('low_risk_allow', 'Permitir acceso si el riesgo es bajo',
         '{"max_risk_score": 39}', 'allow', 3, true, NOW(), NOW());
    """)
    
    conn.commit()
    
    print("\n📊 Políticas CORREGIDAS:")
    print("-" * 80)
    cur.execute("""
        SELECT name, 
               conditions->>'min_risk_score' as min_score,
               conditions->>'max_risk_score' as max_score,
               action
        FROM policies
        ORDER BY priority;
    """)
    
    for row in cur.fetchall():
        print(f"  {row[0]:20} | min:{row[1]:4} | max:{row[2]:4} | {row[3]}")
    
    print("\n✅ ¡CORRECCIÓN COMPLETADA!")
    print("\nAhora deberías ver:")
    print("  medium_risk_stepup | min: 40  | max: 74  | stepup  ✅")
    
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    sys.exit(1)

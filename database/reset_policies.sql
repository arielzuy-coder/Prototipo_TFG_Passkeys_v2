-- ============================================================================
-- Script para resetear las políticas de riesgo a los valores por defecto
-- ============================================================================
-- 
-- Uso:
--   PostgreSQL: psql -U usuario -d database -f reset_policies.sql
--   SQLite: sqlite3 database.db < reset_policies.sql
--
-- Autor: TFG - Sistema de Autenticación Adaptativa
-- Fecha: 2025-10-29
-- ============================================================================

-- Paso 1: Eliminar todas las políticas existentes
DELETE FROM policies;

-- Paso 2: Insertar las políticas por defecto correctas

-- Política 1: Denegar acceso para riesgo alto (score ≥ 75)
INSERT INTO policies (
    id,
    name, 
    description, 
    conditions, 
    action, 
    priority, 
    enabled,
    created_at,
    updated_at
) VALUES (
    gen_random_uuid(),  -- Para PostgreSQL. Si usas SQLite, quita esta línea
    'high_risk_deny',
    'Denegar acceso si el riesgo es alto',
    '{"min_risk_score": 75}',
    'deny',
    1,
    true,
    NOW(),
    NOW()
);

-- Política 2: Requerir step-up para riesgo medio (score 40-74)
INSERT INTO policies (
    id,
    name, 
    description, 
    conditions, 
    action, 
    priority, 
    enabled,
    created_at,
    updated_at
) VALUES (
    gen_random_uuid(),  -- Para PostgreSQL. Si usas SQLite, quita esta línea
    'medium_risk_stepup',
    'Requerir autenticación adicional para riesgo medio',
    '{"min_risk_score": 40, "max_risk_score": 74}',
    'stepup',
    2,
    true,
    NOW(),
    NOW()
);

-- Política 3: Permitir acceso para riesgo bajo (score ≤ 39)
INSERT INTO policies (
    id,
    name, 
    description, 
    conditions, 
    action, 
    priority, 
    enabled,
    created_at,
    updated_at
) VALUES (
    gen_random_uuid(),  -- Para PostgreSQL. Si usas SQLite, quita esta línea
    'low_risk_allow',
    'Permitir acceso si el riesgo es bajo',
    '{"max_risk_score": 39}',
    'allow',
    3,
    true,
    NOW(),
    NOW()
);

-- Paso 3: Verificar que las políticas se insertaron correctamente
SELECT 
    name,
    description,
    conditions,
    action,
    priority,
    enabled
FROM policies
ORDER BY priority ASC;

-- Paso 4: Mostrar resumen
SELECT 
    '✅ Políticas reseteadas correctamente' AS status,
    COUNT(*) AS total_policies
FROM policies
WHERE enabled = true;

-- ============================================================================
-- NOTA: Si usas SQLite en lugar de PostgreSQL:
-- ============================================================================
-- 1. Reemplaza gen_random_uuid() por:
--    - NULL (si el campo es autoincremental)
--    - O genera UUIDs manualmente
-- 
-- 2. Reemplaza NOW() por:
--    - datetime('now')
-- 
-- Ejemplo para SQLite:
-- INSERT INTO policies (name, description, conditions, action, priority, enabled, created_at, updated_at)
-- VALUES ('low_risk_allow', 'Permitir acceso si el riesgo es bajo', 
--         '{"max_risk_score": 39}', 'allow', 3, true, 
--         datetime('now'), datetime('now'));
-- ============================================================================

-- ============================================================================
-- VERIFICACIÓN DE RANGOS
-- ============================================================================
-- Las políticas deben cubrir estos rangos:
--   • Score 0-39:   low_risk_allow    → ALLOW   (acceso directo)
--   • Score 40-74:  medium_risk_stepup → STEPUP (verificación adicional)
--   • Score 75-100: high_risk_deny    → DENY   (acceso denegado)
--
-- Ejemplos de scores según factores:
--   • Dispositivo conocido, horario laboral: ~0-10 → ALLOW
--   • Dispositivo conocido, fuera de horario: ~11-20 → ALLOW  
--   • Dispositivo nuevo, horario laboral: ~30-45 → STEPUP
--   • Dispositivo nuevo + ubicación nueva: ~60-80 → DENY
-- ============================================================================

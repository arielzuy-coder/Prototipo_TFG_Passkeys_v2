-- Script de datos de prueba (seed data)
-- Prototipo de Autenticación Passkeys + Zero Trust

-- Insertar usuarios de prueba
INSERT INTO users (id, email, display_name, status) VALUES
    ('11111111-1111-1111-1111-111111111111', 'admin@prototipo.local', 'Administrador', 'active'),
    ('22222222-2222-2222-2222-222222222222', 'usuario1@prototipo.local', 'Usuario Uno', 'active'),
    ('33333333-3333-3333-3333-333333333333', 'usuario2@prototipo.local', 'Usuario Dos', 'active'),
    ('44444444-4444-4444-4444-444444444444', 'usuario3@prototipo.local', 'Usuario Tres', 'active')
ON CONFLICT (email) DO NOTHING;

-- Insertar políticas de seguridad por defecto
INSERT INTO policies (name, description, conditions, action, priority, enabled) VALUES
    (
        'high_risk_deny',
        'Denegar acceso si el riesgo es alto',
        '{"min_risk_score": 75}',
        'deny',
        1,
        TRUE
    ),
    (
        'medium_risk_stepup',
        'Requerir autenticación adicional para riesgo medio',
        '{"min_risk_score": 40, "max_risk_score": 74}',
        'stepup',
        2,
        TRUE
    ),
    (
        'low_risk_allow',
        'Permitir acceso si el riesgo es bajo',
        '{"max_risk_score": 39}',
        'allow',
        3,
        TRUE
    ),
    (
        'business_hours_only',
        'Permitir acceso solo en horario laboral',
        '{"business_hours_only": true}',
        'deny',
        10,
        FALSE
    ),
    (
        'trusted_devices_only',
        'Permitir solo dispositivos con trust_level > 70',
        '{"min_trust_level": 70}',
        'allow',
        5,
        FALSE
    )
ON CONFLICT (name) DO NOTHING;

-- Comentarios
COMMENT ON TABLE users IS 'Usuarios de prueba para demostración del sistema';
COMMENT ON TABLE policies IS 'Políticas de seguridad predefinidas';
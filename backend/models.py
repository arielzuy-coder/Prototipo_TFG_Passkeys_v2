from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, DECIMAL, JSON, UniqueConstraint, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(100))
    # 'pending' (invitado, sin passkey), 'active', 'suspended'
    status = Column(String(20), default='pending')
    # Perfiles de la tesis (Tabla 4): 'user', 'admin', 'auditor'
    role = Column(String(20), default='user', nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
    passkeys = relationship("Passkey", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")

class Passkey(Base):
    __tablename__ = "passkeys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    credential_id = Column(Text, unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    attestation_fmt = Column(String(50))
    aaguid = Column(String(36))
    counter = Column(Integer, default=0)
    device_name = Column(String(100))
    device_type = Column(String(50))  # 'single_device' | 'multi_device'
    backed_up = Column(Boolean, default=False)
    transports = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime)
    
    user = relationship("User", back_populates="passkeys")

class Device(Base):
    __tablename__ = "devices"
    # La huella es única por usuario (antes era global: un mismo navegador
    # usado por dos personas dejaba a la segunda sin dispositivo registrado)
    __table_args__ = (UniqueConstraint('user_id', 'device_fingerprint', name='uq_devices_user_fingerprint'),)
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    device_fingerprint = Column(String(255), nullable=False, index=True)
    device_name = Column(String(100))
    os = Column(String(50))
    browser = Column(String(50))
    trust_level = Column(Integer, default=50)
    # Passkeys que ya se verificaron desde este dispositivo (H7: la huella sola no alcanza)
    credential_ids = Column(JSON)
    last_seen_ip = Column(String(45))
    last_seen_location = Column(String(100))
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="devices")

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey('devices.id'))
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(Text)
    location = Column(String(100))
    risk_score = Column(DECIMAL(5, 2), default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    # Hash del jti del refresh token vigente (rotación obligatoria)
    refresh_jti_hash = Column(String(64))
    # Verificación continua (UC-03): contexto con el que se abrió la sesión
    credential_id = Column(Text)
    device_fingerprint = Column(String(255))
    country = Column(String(10))
    last_evaluated_at = Column(DateTime)
    # Última autenticación fuerte (login, step-up o re-autenticación con passkey)
    strong_auth_at = Column(DateTime)
    
    user = relationship("User", back_populates="sessions")

class Policy(Base):
    __tablename__ = "policies"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    conditions = Column(JSON, nullable=False)
    action = Column(String(20), nullable=False)
    priority = Column(Integer, default=100)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RiskEvaluation(Base):
    __tablename__ = "risk_evaluations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey('sessions.id'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    risk_score = Column(DECIMAL(5, 2), nullable=False)
    factors = Column(JSON, nullable=False)
    decision = Column(String(20), nullable=False)
    evaluated_at = Column(DateTime, default=datetime.utcnow)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    session_id = Column(UUID(as_uuid=True), ForeignKey('sessions.id'))
    event_type = Column(String(50), nullable=False, index=True)
    event_data = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    # Cadena de integridad (RNF-S4): cada evento sella el anterior con HMAC-SHA256
    chain_seq = Column(BigInteger, unique=True, index=True)
    prev_hash = Column(String(64))
    event_hash = Column(String(64))


class WebAuthnChallenge(Base):
    """Challenge WebAuthn de un solo uso, atado a un usuario y a una ceremonia."""
    __tablename__ = "webauthn_challenges"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    # 'register' | 'login' | 'stepup'
    purpose = Column(String(20), nullable=False)
    # Invitación o transacción de step-up a la que pertenece (opcional)
    ref_id = Column(UUID(as_uuid=True))
    challenge = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)


class Invitation(Base):
    """Invitación de un solo uso para enrolar la primera passkey (alta o recuperación)."""
    __tablename__ = "invitations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    # 'enroll' (alta) | 'recovery' (re-enrolamiento supervisado)
    purpose = Column(String(20), nullable=False, default='enroll')
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)
    revoked = Column(Boolean, default=False)


class StepUpTransaction(Base):
    """Login pendiente de verificación adicional (step-up)."""
    __tablename__ = "stepup_transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    # 'pending' | 'approval_requested' | 'approved' | 'denied' | 'completed' | 'locked'
    status = Column(String(30), nullable=False, default='pending')
    context = Column(JSON, nullable=False)  # ip, user_agent, ubicación, score, credencial usada
    otp_hash = Column(String(64))
    attempts = Column(Integer, default=0)
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime)


class RateLimit(Base):
    """Contador de ventana fija para limitar intentos (por IP, por cuenta, por operación)."""
    __tablename__ = "rate_limits"

    key = Column(String(200), primary_key=True)
    window_start = Column(DateTime, nullable=False)
    count = Column(Integer, nullable=False, default=0)


class SusResponse(Base):
    """Respuesta anónima al cuestionario System Usability Scale (RNF-U2)."""
    __tablename__ = "sus_responses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    answers = Column(JSON, nullable=False)        # 10 valores de 1 a 5, en el orden del cuestionario
    score = Column(DECIMAL(5, 2), nullable=False)  # 0 a 100
    profile = Column(String(20))                   # perfil con el que probó el sistema (opcional)
    comment = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

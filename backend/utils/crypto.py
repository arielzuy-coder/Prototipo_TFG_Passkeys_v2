from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from typing import Tuple

class CryptoHelper:
    """Utilidades criptográficas para el sistema."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Genera una clave criptográfica aleatoria."""
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Encripta datos usando Fernet (AES)."""
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """Desencripta datos."""
        f = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    
    @staticmethod
    def generate_random_token(length: int = 32) -> str:
        """Genera un token aleatorio seguro."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def derive_key_from_password(
        password: str,
        salt: bytes = None
    ) -> Tuple[bytes, bytes]:
        """Deriva una clave criptográfica desde una contraseña."""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        return key, salt
    
    @staticmethod
    def hash_data(data: str) -> str:
        """Genera un hash SHA-256 de los datos."""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode())
        return base64.b64encode(digest.finalize()).decode()
"""
Geolocalización de IPs (país).

- GEOIP_PROVIDER=local (por defecto): base GeoLite2 incluida en el paquete geoip2fast.
  No depende de un servicio externo y la IP del usuario no sale del servidor (RNF-N2).
- GEOIP_PROVIDER=ipapi: consulta ipapi.co (da ciudad, pero en Render responde 429 porque
  la IP de salida es compartida y la cuota gratuita está agotada).
- GEOIP_PROVIDER=none: sin geolocalización.
- IPs privadas/loopback: ubicación desconocida, o LOCAL_IP_COUNTRY en desarrollo.
"""
import ipaddress
import logging
import threading
import time
from typing import Dict

import requests

from config import settings

logger = logging.getLogger(__name__)

_cache: Dict[str, tuple] = {}
_local_db = None
_lock = threading.Lock()
_MAX_ENTRIES = 5000

COUNTRY_NAMES = {"AR": "Argentina"}


def _unknown(ip: str, display: str = None) -> Dict[str, str]:
    return {"country": "Unknown", "country_name": "Unknown", "city": "Unknown",
            "display": display or f"IP: {ip}"}


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # "testclient", "unknown", etc.
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def lookup(ip: str) -> Dict[str, str]:
    if is_private(ip):
        if settings.LOCAL_IP_COUNTRY:
            cc = settings.LOCAL_IP_COUNTRY.upper()
            return {"country": cc, "country_name": COUNTRY_NAMES.get(cc, cc), "city": "Red local",
                    "display": "Red local (desarrollo)"}
        return _unknown(ip, "Red privada")

    provider = settings.GEOIP_PROVIDER.lower()
    if provider == "local":
        return _lookup_local(ip)
    if provider != "ipapi":
        return _unknown(ip)

    now = time.time()
    with _lock:
        hit = _cache.get(ip)
        if hit and now - hit[0] < settings.GEOIP_CACHE_SECONDS:
            return hit[1]

    result = _unknown(ip)
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if not data.get("error"):
                country = data.get("country_code") or "Unknown"
                city = data.get("city") or "Unknown"
                country_name = data.get("country_name") or "Unknown"
                result = {"country": country, "country_name": country_name, "city": city,
                          "display": f"{city}, {country_name}"}
        else:
            logger.warning("[GEOLOCATION] API respondió %s", response.status_code)
    except Exception as e:
        logger.warning("[GEOLOCATION] Sin datos para la IP: %s", type(e).__name__)
        return result  # no se cachea un error transitorio

    with _lock:
        if len(_cache) >= _MAX_ENTRIES:
            _cache.clear()
        _cache[ip] = (now, result)
    return result


def _local():
    """Carga perezosa de la base local (~0,1 s, ~60 MB en memoria con IPv6)."""
    global _local_db
    if _local_db is None:
        with _lock:
            if _local_db is None:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    from geoip2fast import GeoIP2Fast
                _local_db = GeoIP2Fast(geoip2fast_data_file="geoip2fast-ipv6.dat.gz", verbose=False)
    return _local_db


def _lookup_local(ip: str) -> Dict[str, str]:
    try:
        r = _local().lookup(ip)
    except Exception as e:
        logger.warning("[GEOLOCATION] Base local sin datos: %s", type(e).__name__)
        return _unknown(ip)
    code = getattr(r, "country_code", "") or ""
    if len(code) != 2 or not code.isalpha():  # "--" = no encontrada / privada
        return _unknown(ip)
    name = getattr(r, "country_name", code) or code
    return {"country": code, "country_name": name, "city": "Unknown", "display": name}

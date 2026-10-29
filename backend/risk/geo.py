"""
Geolocalización de IPs con caché.

- IPs privadas/loopback: no se consultan afuera. Por defecto quedan como ubicación
  desconocida; LOCAL_IP_COUNTRY permite asignarles un país en desarrollo.
- GEOIP_PROVIDER=none desactiva la consulta externa (minimización de datos, RNF-N2).
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

    if settings.GEOIP_PROVIDER.lower() != "ipapi":
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

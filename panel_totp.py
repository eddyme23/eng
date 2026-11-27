"""RFC 6238 six-digit authenticator codes (30-second step, SHA-1)."""
import base64
import hashlib
import hmac
import secrets
import struct
import time


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def code(secret, counter):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    value = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = value[-1] & 15
    number = struct.unpack('>I', value[offset:offset + 4])[0] & 0x7fffffff
    return f'{number % 1000000:06d}'


def verify(secret, candidate, now=None):
    if not isinstance(candidate, str) or len(candidate) != 6 or not candidate.isascii() or not candidate.isdigit():
        return None
    step = int((time.time() if now is None else now) // 30)
    for counter in (step, step - 1, step + 1):
        if counter >= 0 and hmac.compare_digest(code(secret, counter), candidate):
            return counter
    return None

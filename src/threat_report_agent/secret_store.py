from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet


class SecretCipher:
    def __init__(self, key_material: str) -> None:
        if not key_material:
            raise ValueError("GATE_SECRET_KEY must be configured before accepting secrets")
        derived = hashlib.sha256(key_material.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")

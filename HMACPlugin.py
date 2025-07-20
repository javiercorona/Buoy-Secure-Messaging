import hmac
import hashlib
from typing import Tuple, Dict, Any
from your_main_file import BuoyPlugin  # Adjust import path if needed

class HMACPlugin(BuoyPlugin):
    """
    Adds HMAC-based authentication for message integrity.
    Computes HMAC-SHA256 over ciphertext + serialized context.
    """

    version = "1.0"

    def __init__(self, cipher):
        super().__init__(cipher)
        # Derive a separate key from shared secret (optional)
        self.hmac_key = hashlib.sha256(cipher.shared_secret.encode()).digest()

    def post_encrypt(self, ciphertext: bytes, context: Dict[str, Any]) -> bytes:
        # Serialize context deterministically
        import json
        ctx_bytes = json.dumps(context, sort_keys=True).encode('utf-8')
        mac = hmac.new(self.hmac_key, ciphertext + ctx_bytes, hashlib.sha256).digest()
        # Store the MAC hex in plugin context for transport
        context['plugins'][self.__class__.__name__] = mac.hex()
        return ciphertext

    def pre_decrypt(self, ciphertext: bytes, context: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        import json
        expected_mac_hex = context.get('plugins', {}).get(self.__class__.__name__)
        if not expected_mac_hex:
            raise ValueError("HMACPlugin: Missing authentication MAC in context.")

        ctx_bytes = json.dumps(context, sort_keys=True).encode('utf-8')
        expected_mac = bytes.fromhex(expected_mac_hex)
        actual_mac = hmac.new(self.hmac_key, ciphertext + ctx_bytes, hashlib.sha256).digest()

        if not hmac.compare_digest(actual_mac, expected_mac):
            raise ValueError("HMACPlugin: Authentication failed, message tampered or corrupted.")

        return ciphertext, context

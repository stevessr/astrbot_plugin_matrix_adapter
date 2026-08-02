"""Device and one-time-key signature verification helpers."""

from astrbot.api import logger

from ...verification.crypto_utils import _canonical_json
from ..types import Ed25519PublicKey, Ed25519Signature


class OlmMachineKeyVerificationMixin:
    """Matrix 设备密钥与一次性密钥签名校验能力。"""

    @classmethod
    def verify_json_signature(
        cls,
        payload: dict,
        signer_user_id: str,
        signing_key_id: str,
        public_key: str,
    ) -> bool:
        """Verify a Matrix signed JSON object with an Ed25519 public key.

        Matrix signatures cover canonical JSON with the top-level ``unsigned``
        and ``signatures`` properties removed.  Invalid/missing material is a
        normal protocol failure and is therefore reported as ``False`` rather
        than escaping a crypto-library exception.
        """
        if not all(
            isinstance(value, str) and value
            for value in (signer_user_id, signing_key_id, public_key)
        ) or not isinstance(payload, dict):
            return False

        signatures = payload.get("signatures")
        if not isinstance(signatures, dict):
            return False
        user_signatures = signatures.get(signer_user_id)
        if not isinstance(user_signatures, dict):
            return False
        signature_b64 = user_signatures.get(signing_key_id)
        if not isinstance(signature_b64, str) or not signature_b64:
            return False

        signed_payload = dict(payload)
        signed_payload.pop("unsigned", None)
        signed_payload.pop("signatures", None)
        try:
            verifier = Ed25519PublicKey.from_base64(public_key)
            signature = Ed25519Signature.from_base64(signature_b64)
            verifier.verify_signature(
                _canonical_json(signed_payload).encode("utf-8"),
                signature,
            )
            return True
        except Exception as e:
            logger.debug(f"Matrix signed JSON verification failed: {e}")
            return False

    @classmethod
    def verify_device_keys(
        cls,
        user_id: str,
        device_id: str,
        device_info: dict,
    ) -> bool:
        """Validate a device-keys object and its mandatory self-signature."""
        if not isinstance(device_info, dict):
            return False
        if device_info.get("user_id") != user_id:
            return False
        if device_info.get("device_id") != device_id:
            return False
        algorithms = device_info.get("algorithms")
        if not isinstance(algorithms, list) or not all(
            isinstance(algorithm, str) and algorithm for algorithm in algorithms
        ):
            return False
        keys = device_info.get("keys")
        if not isinstance(keys, dict):
            return False
        ed25519_key_id = f"ed25519:{device_id}"
        ed25519_key = keys.get(ed25519_key_id)
        curve25519_key = keys.get(f"curve25519:{device_id}")
        if not isinstance(ed25519_key, str) or not ed25519_key:
            return False
        if not isinstance(curve25519_key, str) or not curve25519_key:
            return False
        return cls.verify_json_signature(
            device_info,
            user_id,
            ed25519_key_id,
            ed25519_key,
        )

    @classmethod
    def select_verified_one_time_key(
        cls,
        user_id: str,
        device_id: str,
        device_ed25519_key: str,
        device_one_time_keys: dict,
    ) -> tuple[str, str] | None:
        """Return the first valid signed_curve25519 one-time/fallback key.

        Claimed keys are controlled by the homeserver until their device
        signature is verified.  Never fall back to accepting a raw or invalid
        key: doing so would allow a malicious server to establish its own Olm
        session in place of the target device.
        """
        if not isinstance(device_one_time_keys, dict):
            return None
        signing_key_id = f"ed25519:{device_id}"
        for key_id, key_data in device_one_time_keys.items():
            if not isinstance(key_id, str) or not key_id.startswith(
                "signed_curve25519:"
            ):
                continue
            if not isinstance(key_data, dict):
                continue
            curve_key = key_data.get("key")
            if not isinstance(curve_key, str) or not curve_key:
                continue
            if cls.verify_json_signature(
                key_data,
                user_id,
                signing_key_id,
                device_ed25519_key,
            ):
                return key_id, curve_key
        return None

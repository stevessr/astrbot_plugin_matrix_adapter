"""Matrix signed-JSON verification."""

from astrbot.api import logger

from ....verification.crypto_utils import _canonical_json
from ...types import Ed25519PublicKey, Ed25519Signature


class OlmMachineKeyJSONSignatureMixin:
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

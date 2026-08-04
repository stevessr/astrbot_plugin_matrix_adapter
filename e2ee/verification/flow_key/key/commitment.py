"""SAS commitment digest verification."""

import hashlib

from astrbot.api import logger

from ...crypto_utils import _canonical_json, _encode_unpadded_base64


class SASVerificationFlowKeyCommitmentMixin:
    """Verify the accept sender's commitment against the start content."""

    def _verify_commitment(
        self,
        their_key: str,
        start_content,
        their_commitment,
    ) -> bool:
        """Return True when the commitment matches the public key digest.

        The start sender validates the accept sender's commitment once it
        receives that sender's public key. Hash the exact start *content*
        object and encode the digest as unpadded Base64 (Matrix v1.19).
        """
        combined = (their_key + _canonical_json(start_content)).encode("utf-8")
        computed = _encode_unpadded_base64(hashlib.sha256(combined).digest())

        if computed != their_commitment:
            logger.warning(
                "[E2EE-Verify] Commitment 验证失败！"
                f"expected={(their_commitment if isinstance(their_commitment, str) else '')[:16]}... "
                f"computed={(computed or '')[:16]}..."
            )
            return False
        return True

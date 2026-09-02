import types
import unittest
from unittest import mock

from test_matrix_new_spec_compat import load_module


class MatrixV101QRPayloadTests(unittest.TestCase):
    def test_qr_request_id_uses_utf8_byte_length(self):
        payload_mod = load_module("e2ee.verification.utils.qr.payload")
        decoding_mod = load_module("e2ee.verification.sas.qr.decoding")

        builder = payload_mod.SASVerificationFlowQRPayloadMixin()
        builder._decode_unpadded_base64 = lambda value: (
            b"A" * 32 if value == "first" else b"B" * 32
        )
        transaction_id = "$验证:example.org"
        payload = builder._build_self_verification_qr_payload(
            transaction_id,
            "first",
            "second",
            b"12345678",
            0x01,
        )

        transaction_bytes = transaction_id.encode("utf-8")
        self.assertEqual(int.from_bytes(payload[8:10], "big"), len(transaction_bytes))
        self.assertEqual(payload[10 : 10 + len(transaction_bytes)], transaction_bytes)

        parsed = decoding_mod.SASVerificationQRDecodingMixin._parse_verification_qr_payload(
            payload
        )
        self.assertEqual(parsed["transaction_id"], transaction_id)
        self.assertEqual(parsed["secret"], b"12345678")

    def test_qr_parser_rejects_unknown_mode(self):
        decoding_mod = load_module("e2ee.verification.sas.qr.decoding")
        payload = b"MATRIX" + bytes([0x02, 0x7F]) + b"\x00\x01x" + b"A" * 32 + b"B" * 32 + b"secret"

        with self.assertRaisesRegex(ValueError, "二维码模式"):
            decoding_mod.SASVerificationQRDecodingMixin._parse_verification_qr_payload(
                payload
            )

    def test_qr_parser_rejects_invalid_utf8_request_id(self):
        decoding_mod = load_module("e2ee.verification.sas.qr.decoding")
        payload = b"MATRIX" + bytes([0x02, 0x01]) + b"\x00\x01\xff" + b"A" * 32 + b"B" * 32 + b"secret"

        with self.assertRaisesRegex(ValueError, "UTF-8"):
            decoding_mod.SASVerificationQRDecodingMixin._parse_verification_qr_payload(
                payload
            )


class MatrixV101QRScanTests(unittest.IsolatedAsyncioTestCase):
    async def test_key_mismatch_sends_cancel_and_does_not_reciprocate(self):
        scanning_mod = load_module("e2ee.verification.sas.qr.scanning")
        crypto = load_module("constants.crypto")

        scanner = scanning_mod.SASVerificationQRScanningMixin()
        scanner.user_id = "@alice:example.org"
        scanner.device_id = "CURRENT"
        scanner.olm = types.SimpleNamespace(ed25519_key="current-key")
        scanner.client = types.SimpleNamespace(
            query_keys=mock.AsyncMock(
                return_value={
                    "device_keys": {
                        "@alice:example.org": {
                            "PEER": {"keys": {"ed25519:PEER": "peer-key"}}
                        }
                    },
                    "master_keys": {
                        "@alice:example.org": {
                            "keys": {"ed25519:MASTER": "master-key"}
                        }
                    },
                }
            )
        )
        scanner._load_qr_payload_bytes = lambda _value: b"payload"
        scanner._parse_verification_qr_payload = lambda _payload: {
            "transaction_id": "txn",
            "mode": crypto.QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER,
            "key1": b"X" * 32,
            "key2": b"Y" * 32,
            "secret": b"12345678",
        }
        session = {}
        scanner._find_session_for_qr_scan = lambda *_args: ("txn", session)
        scanner._send_cancel = mock.AsyncMock()
        scanner._send_to_device = mock.AsyncMock()

        ok, _message = await scanner.scan_qr(
            "@alice:example.org", "PEER", "ignored"
        )

        self.assertFalse(ok)
        self.assertEqual(session["state"], "cancelled")
        self.assertIs(session["qr_confirmed"], False)
        scanner._send_cancel.assert_awaited_once_with(
            "@alice:example.org",
            "PEER",
            "txn",
            "m.key_mismatch",
            "QR code keys do not match the verification session",
        )
        scanner._send_to_device.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

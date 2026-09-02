import base64
import hashlib
import hmac
import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV106TimestampTests(unittest.IsolatedAsyncioTestCase):
    async def test_timestamp_to_event_uses_stable_endpoint(self):
        mod = load_module("client.room_state.inspection.endpoints")
        calls = []

        class Client(mod.RoomStateInspectionEndpointMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"event_id": "$event", "origin_server_ts": 1234}

        result = await Client().timestamp_to_event(
            "!room:example.org", 1234, direction="f"
        )
        self.assertEqual(result["event_id"], "$event")
        self.assertEqual(
            calls[0][1],
            "/_matrix/client/v3/rooms/%21room%3Aexample.org/timestamp_to_event",
        )
        self.assertEqual(calls[0][2]["params"], {"ts": 1234, "dir": "f"})

    async def test_timestamp_to_event_rejects_bad_direction(self):
        mod = load_module("client.room_state.inspection.endpoints")
        with self.assertRaises(ValueError):
            await mod.RoomStateInspectionEndpointMixin().timestamp_to_event(
                "!room:example.org", 1, direction="sideways"
            )


class MatrixV106ErrorTests(unittest.TestCase):
    def test_unrecognized_endpoint_is_distinct_from_not_found(self):
        errors = load_module("client.base.errors")
        unsupported = errors.MatrixAPIError(
            404,
            {"errcode": "M_UNRECOGNIZED", "error": "Unrecognized request"},
            "unsupported",
        )
        missing = errors.MatrixAPIError(
            404,
            {"errcode": "M_NOT_FOUND", "error": "Unknown event"},
            "missing",
        )
        self.assertTrue(unsupported.is_unrecognized)
        self.assertTrue(unsupported.is_endpoint_unsupported)
        self.assertFalse(missing.is_endpoint_unsupported)


class MatrixV106SASMacTests(unittest.TestCase):
    def test_v2_fallback_is_hkdf_then_hmac_with_unpadded_base64(self):
        kdf = load_module("e2ee.verification.crypto_utils.kdf")
        shared = bytes(range(32))
        message = "ed25519-public-key"
        info = "MATRIX_KEY_VERIFICATION_MAC@a:example.orgA@b:example.orgBtxnKEY"

        # Independent RFC5869/HMAC-SHA256 calculation.
        salt = b"\x00" * 32
        prk = hmac.new(salt, shared, hashlib.sha256).digest()
        okm = hmac.new(prk, info.encode() + b"\x01", hashlib.sha256).digest()
        expected_raw = hmac.new(okm, message.encode(), hashlib.sha256).digest()
        expected = base64.b64encode(expected_raw).decode("ascii").rstrip("=")

        actual = kdf._calculate_sas_mac(
            method="hkdf-hmac-sha256.v2",
            message=message,
            info=info,
            shared_secret=shared,
        )
        self.assertEqual(actual, expected)
        self.assertNotIn("=", actual)

    def test_legacy_mac_without_compat_backend_fails_closed(self):
        kdf = load_module("e2ee.verification.crypto_utils.kdf")
        with self.assertRaises(RuntimeError):
            kdf._calculate_sas_mac(
                method="hkdf-hmac-sha256",
                message="key",
                info="info",
                shared_secret=b"x" * 32,
            )


if __name__ == "__main__":
    unittest.main()

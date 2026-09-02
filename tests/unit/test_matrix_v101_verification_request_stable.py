import unittest
from unittest import mock

from test_matrix_new_spec_compat import load_module


class MatrixV101VerificationRequestWindowTests(unittest.IsolatedAsyncioTestCase):
    def test_timestamp_window_accepts_exact_boundaries(self):
        request_mod = load_module("e2ee.verification.flow_start.request.core")
        cls = request_mod.SASVerificationFlowRequestCoreMixin

        with mock.patch.object(request_mod.time, "time", return_value=1000.0):
            self.assertTrue(
                cls._is_fresh_to_device_verification_request(1000000 - 10 * 60 * 1000)
            )
            self.assertTrue(
                cls._is_fresh_to_device_verification_request(1000000 + 5 * 60 * 1000)
            )
            self.assertFalse(
                cls._is_fresh_to_device_verification_request(
                    1000000 - 10 * 60 * 1000 - 1
                )
            )
            self.assertFalse(
                cls._is_fresh_to_device_verification_request(
                    1000000 + 5 * 60 * 1000 + 1
                )
            )
            self.assertFalse(cls._is_fresh_to_device_verification_request(None))
            self.assertFalse(cls._is_fresh_to_device_verification_request(True))

    async def test_stale_request_does_not_create_verification_session(self):
        request_mod = load_module("e2ee.verification.flow_start.request.core")
        handler = request_mod.SASVerificationFlowRequestCoreMixin()
        handler._sessions = {}
        handler._mask_identifier = lambda value: value
        handler._query_request_verification_keys = mock.AsyncMock()
        handler._dispatch_verification_mode = mock.AsyncMock()

        with mock.patch.object(request_mod.time, "time", return_value=1000.0):
            await handler._handle_request(
                "@alice:example.org",
                {
                    "from_device": "ALICEDEVICE",
                    "methods": ["m.sas.v1"],
                    "timestamp": 1000000 - 10 * 60 * 1000 - 1,
                },
                "old-transaction",
            )

        self.assertEqual(handler._sessions, {})
        handler._query_request_verification_keys.assert_not_awaited()
        handler._dispatch_verification_mode.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

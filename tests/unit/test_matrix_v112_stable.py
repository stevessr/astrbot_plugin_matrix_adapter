import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV112AccountLockingTests(unittest.IsolatedAsyncioTestCase):
    async def test_locked_account_preserves_session_and_skips_refresh(self):
        mod = load_module("sync.core.loop.failure")
        errors = load_module("client.base.errors")
        sleeps = []
        refresh_calls = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)

        async def on_token_invalid():
            refresh_calls.append(True)
            return True

        original_sleep = mod.asyncio.sleep
        mod.asyncio.sleep = fake_sleep
        try:
            handler = mod.MatrixSyncManagerLoopFailureMixin()
            handler._last_sync_failure_at = None
            handler._sync_failure_count = 0
            handler._last_sync_error = None
            handler._sync_consecutive_failures = 0
            handler.on_token_invalid = on_token_invalid
            await handler._handle_sync_api_error(
                errors.MatrixAPIError(
                    401,
                    {
                        "errcode": "M_USER_LOCKED",
                        "soft_logout": True,
                        "error": "account locked",
                    },
                    "account locked",
                )
            )
        finally:
            mod.asyncio.sleep = original_sleep

        self.assertEqual(refresh_calls, [])
        self.assertEqual(sleeps, [10])

    async def test_only_token_invalid_errcodes_trigger_refresh(self):
        mod = load_module("sync.core.loop.failure")
        errors = load_module("client.base.errors")
        refresh_calls = []

        async def fake_sleep(_seconds):
            return None

        async def on_token_invalid():
            refresh_calls.append(True)
            return True

        original_sleep = mod.asyncio.sleep
        mod.asyncio.sleep = fake_sleep
        try:
            handler = mod.MatrixSyncManagerLoopFailureMixin()
            handler._last_sync_failure_at = None
            handler._sync_failure_count = 0
            handler._last_sync_error = None
            handler._sync_consecutive_failures = 0
            handler.on_token_invalid = on_token_invalid
            await handler._handle_sync_api_error(
                errors.MatrixAPIError(
                    401,
                    {"errcode": "M_UNKNOWN_TOKEN", "soft_logout": True},
                    "expired token",
                )
            )
        finally:
            mod.asyncio.sleep = original_sleep

        self.assertEqual(refresh_calls, [True])

    def test_user_locked_error_helper_preserves_soft_logout_hint(self):
        errors = load_module("client.base.errors")
        error = errors.MatrixAPIError(
            401,
            {"errcode": "M_USER_LOCKED", "soft_logout": True},
            "locked",
        )
        self.assertTrue(error.is_user_locked)
        self.assertTrue(error.soft_logout)


class MatrixV112LoginTokenTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_login_token_capability_requires_explicit_enabled(self):
        mod = load_module("client.auth.discovery.capabilities")

        class Client(mod.AuthDiscoveryCapabilitiesMixin):
            def __init__(self, capability):
                self.capability = capability

            async def get_capabilities(self):
                return {"capabilities": {"m.get_login_token": self.capability}}

        self.assertTrue(await Client({"enabled": True}).can_get_login_token())
        self.assertFalse(await Client({"enabled": False}).can_get_login_token())
        self.assertFalse(await Client({}).can_get_login_token())

    async def test_generate_login_token_uses_v1_uia_endpoint(self):
        mod = load_module("client.auth.login.registration")
        calls = []

        class Client(mod.AuthLoginRegistrationMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"login_token": "once", "expires_in_ms": 120000}

        auth = {"type": "m.login.password", "session": "uia-session"}
        response = await Client().generate_login_token(auth=auth)

        self.assertEqual(response["login_token"], "once")
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][1], "/_matrix/client/v1/login/get_token")
        self.assertEqual(calls[0][2]["data"], {"auth": auth})


if __name__ == "__main__":
    unittest.main()

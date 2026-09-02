import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV102EventTests(unittest.TestCase):
    def test_prev_content_comes_from_unsigned_only(self):
        mod = load_module("client.event_types.base")
        event = mod.MatrixEvent.from_dict(
            {
                "event_id": "$state",
                "sender": "@alice:example.org",
                "origin_server_ts": 1,
                "type": "m.room.name",
                "content": {"name": "new"},
                "prev_content": {"name": "obsolete-top-level"},
                "unsigned": {"prev_content": {"name": "old"}},
            },
            "!room:example.org",
        )
        self.assertEqual(event.prev_content, {"name": "old"})

    def test_missing_unsigned_prev_content_is_none(self):
        mod = load_module("client.event_types.base")
        event = mod.MatrixEvent.from_dict(
            {"type": "m.room.name", "prev_content": {"name": "legacy"}},
            "!room:example.org",
        )
        self.assertIsNone(event.prev_content)


class MatrixV102RegistrationTokenTests(unittest.IsolatedAsyncioTestCase):
    async def test_registration_token_validity_is_unauthenticated(self):
        mod = load_module("client.auth.login.registration")
        calls = []

        class Client(mod.AuthLoginRegistrationMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"valid": True}

        self.assertTrue(await Client().check_registration_token("invite-token"))
        method, endpoint, kwargs = calls[0]
        self.assertEqual(method, "GET")
        self.assertEqual(
            endpoint,
            "/_matrix/client/v1/register/m.login.registration_token/validity",
        )
        self.assertEqual(kwargs["params"], {"token": "invite-token"})
        self.assertFalse(kwargs["authenticated"])

    async def test_empty_registration_token_is_rejected(self):
        mod = load_module("client.auth.login.registration")
        with self.assertRaises(ValueError):
            await mod.AuthLoginRegistrationMixin().check_registration_token("   ")


if __name__ == "__main__":
    unittest.main()

import unittest
from urllib.parse import parse_qs, urlsplit

from test_matrix_new_spec_compat import load_module


class StableAccountDataMSCTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.profile.account.account_data")

    def _make_client(self, initial=None):
        calls = []
        state = dict(initial or {})

        class Client(self.mod.ProfileAccountDataMixin):
            user_id = "@bot:example.org"

            async def _request(self, method, endpoint, data=None, **kwargs):
                calls.append((method, endpoint, data))
                key = endpoint.rsplit("/", 1)[-1]
                if method == "GET":
                    return state.get(key, {})
                state[key] = data
                return {}

        return Client(), calls, state

    async def test_recent_emoji_records_and_moves_to_front(self):
        client, _, state = self._make_client(
            {
                "m.recent_emoji": {
                    "recent_emoji": [
                        {"emoji": "🙂", "total": 2},
                        {"emoji": "🚀", "total": 1},
                    ]
                }
            }
        )

        updated = await client.record_recent_emoji("🚀", increment=3)

        self.assertEqual(updated[0], {"emoji": "🚀", "total": 4})
        self.assertEqual(updated[1], {"emoji": "🙂", "total": 2})
        self.assertEqual(state["m.recent_emoji"]["recent_emoji"], updated)

    async def test_invite_blocking_uses_stable_account_data(self):
        client, _, state = self._make_client()
        await client.set_invite_blocking(True)
        self.assertEqual(
            state["m.invite_permission_config"], {"default_action": "block"}
        )
        self.assertTrue(await client.get_invite_blocking())


class StableCapabilityMSCTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.auth.discovery.capabilities")

    async def test_forced_forget_capability_defaults_false_and_reads_enabled(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            enabled = False

            async def _request(self, method, endpoint, **kwargs):
                if self.enabled:
                    return {
                        "capabilities": {
                            "m.forget_forced_upon_leave": {"enabled": True}
                        }
                    }
                return {"capabilities": {}}

        client = Client()
        self.assertFalse(await client.is_forget_forced_upon_leave())
        client.enabled = True
        self.assertTrue(await client.is_forget_forced_upon_leave())

    async def test_account_moderation_capability_defaults_and_values(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                return {
                    "capabilities": {
                        "m.account_moderation": {"lock": True, "suspend": False}
                    }
                }

        client = Client()
        self.assertEqual(
            await client.get_account_moderation_capability(),
            {"lock": True, "suspend": False},
        )

    async def test_dev_msc4357_probe_remains_available(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                return {
                    "unstable_features": {
                        "org.matrix.msc4357.stable": True,
                    }
                }

        self.assertTrue(await Client().get_msc4357_server_advertisement())


class StableModerationMSCTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.message.receipts.events.modify")

    def _make_client(self):
        calls = []

        class Client(self.mod.MessageEventModifyMixin):
            async def _request(self, method, endpoint, data=None, **kwargs):
                calls.append((method, endpoint, data))
                return {"event_id": "$ok"}

        return Client(), calls

    async def test_redaction_uses_normal_send_endpoint_by_default(self):
        client, calls = self._make_client()
        await client.redact_event(
            "!room:example.org", "$event:example.org", reason="spam", txn_id="txn"
        )
        method, endpoint, data = calls[-1]
        self.assertEqual(method, "PUT")
        self.assertIn("/send/m.room.redaction/txn", endpoint)
        self.assertEqual(data, {"redacts": "$event:example.org", "reason": "spam"})

    async def test_legacy_redaction_endpoint_remains_available(self):
        client, calls = self._make_client()
        await client.redact_event(
            "!room:example.org",
            "$event:example.org",
            txn_id="txn",
            use_legacy_endpoint=True,
        )
        _, endpoint, data = calls[-1]
        self.assertIn("/redact/%24event%3Aexample.org/txn", endpoint)
        self.assertEqual(data, {})

    async def test_report_event_does_not_send_removed_score(self):
        client, calls = self._make_client()
        await client.report_event(
            "!room:example.org", "$event:example.org", score=-100, reason="spam"
        )
        method, endpoint, data = calls[-1]
        self.assertEqual(method, "POST")
        self.assertIn("/report/", endpoint)
        self.assertEqual(data, {"reason": "spam"})

    async def test_room_and_user_report_endpoints(self):
        client, calls = self._make_client()
        await client.report_room("!room:example.org", "bad room")
        await client.report_user("@alice:example.org", "bad user")
        self.assertTrue(calls[-2][1].endswith("/rooms/%21room%3Aexample.org/report"))
        self.assertTrue(calls[-1][1].endswith("/users/%40alice%3Aexample.org/report"))


class StableAccountModerationMSCTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.user.moderation.account")

    async def test_lock_and_suspend_use_stable_admin_endpoints(self):
        calls = []

        class Client(self.mod.UserAccountModerationMixin):
            async def _request(self, method, endpoint, data=None, **kwargs):
                calls.append((method, endpoint, data))
                return data or {"locked": False}

        client = Client()
        await client.set_user_suspension("@alice:example.org", True)
        await client.set_user_lock("@alice:example.org", False)
        await client.get_user_lock("@alice:example.org")

        self.assertEqual(
            calls[0],
            (
                "PUT",
                "/_matrix/client/v1/admin/suspend/%40alice%3Aexample.org",
                {"suspended": True},
            ),
        )
        self.assertEqual(
            calls[1],
            (
                "PUT",
                "/_matrix/client/v1/admin/lock/%40alice%3Aexample.org",
                {"locked": False},
            ),
        )
        self.assertEqual(
            calls[2],
            (
                "GET",
                "/_matrix/client/v1/admin/lock/%40alice%3Aexample.org",
                None,
            ),
        )


class StableOAuthMSCTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_module("auth.oauth2.discovery.metadata")

    def _metadata(self):
        return {
            "issuer": "https://auth.example.org/",
            "authorization_endpoint": "https://auth.example.org/authorize",
            "token_endpoint": "https://auth.example.org/token",
            "revocation_endpoint": "https://auth.example.org/revoke",
            "registration_endpoint": "https://auth.example.org/register",
            "device_authorization_endpoint": "https://auth.example.org/device",
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                self.mod.DEVICE_CODE_GRANT_TYPE,
            ],
            "account_management_uri": "https://auth.example.org/account?lang=en",
            "account_management_actions_supported": [
                "org.matrix.profile",
                "org.matrix.device_delete",
            ],
        }

    def test_device_grant_and_account_management_metadata_are_preserved(self):
        class OAuth(self.mod.MatrixOAuth2DiscoveryMetadataMixin):
            pass

        oauth = OAuth()
        result = oauth._apply_discovered_oauth_metadata(self._metadata())
        self.assertTrue(oauth.supports_device_authorization_grant())
        self.assertEqual(
            result["device_authorization_endpoint"],
            "https://auth.example.org/device",
        )
        self.assertEqual(
            result["account_management_actions_supported"],
            ["org.matrix.profile", "org.matrix.device_delete"],
        )

    def test_account_management_deep_link_preserves_query(self):
        class OAuth(self.mod.MatrixOAuth2DiscoveryMetadataMixin):
            pass

        oauth = OAuth()
        oauth._apply_discovered_oauth_metadata(self._metadata())
        url = oauth.get_account_management_url(
            "org.matrix.device_delete", device_id="DEVICE 1"
        )
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["lang"], ["en"])
        self.assertEqual(query["action"], ["org.matrix.device_delete"])
        self.assertEqual(query["device_id"], ["DEVICE 1"])

    def test_unadvertised_account_management_action_is_rejected(self):
        class OAuth(self.mod.MatrixOAuth2DiscoveryMetadataMixin):
            pass

        oauth = OAuth()
        oauth._apply_discovered_oauth_metadata(self._metadata())
        with self.assertRaises(ValueError):
            oauth.get_account_management_url("org.matrix.account_deactivate")


class StableFormattedHTMLMSCTests(unittest.TestCase):
    def test_ordered_list_start_attribute_is_preserved_in_plain_fallback(self):
        mod = load_module("receiver.events.text.formatting.plain")
        text = mod._plain_from_html(
            '<ol start="3"><li>third</li><li>fourth</li></ol>'
        )
        self.assertIn("3. third", text)
        self.assertIn("4. fourth", text)


class StableErrorMSCTests(unittest.TestCase):
    def test_user_limit_exceeded_exposes_admin_contact(self):
        mod = load_module("client.base.errors")
        error = mod.MatrixAPIError(
            403,
            {
                "errcode": "M_USER_LIMIT_EXCEEDED",
                "error": "quota exceeded",
                "admin_contact": "mailto:admin@example.org",
            },
            "quota exceeded",
        )
        self.assertTrue(error.is_user_limit_exceeded)
        self.assertEqual(error.errcode, "M_USER_LIMIT_EXCEEDED")
        self.assertEqual(error.admin_contact, "mailto:admin@example.org")


class StableAnimatedMediaMSCTests(unittest.TestCase):
    def test_image_content_includes_is_animated(self):
        mod = load_module("sender.events.image.content")
        content = mod._build_image_content(
            "mxc://example.org/image",
            "image.gif",
            "image/gif",
            123,
            320,
            240,
            is_animated=True,
        )
        self.assertTrue(content["info"]["is_animated"])

    def test_sticker_round_trip_preserves_is_animated(self):
        models = load_module("sticker.component.models")
        sticker_mod = load_module("sticker.component.sticker")
        sticker = sticker_mod.Sticker(
            body="animated",
            url="mxc://example.org/sticker",
            info=models.StickerInfo(mimetype="image/gif", is_animated=True),
        )
        content = sticker.to_matrix_content()
        restored = sticker_mod.Sticker.from_matrix_event(content)
        self.assertTrue(content["info"]["is_animated"])
        self.assertTrue(restored.info.is_animated)


if __name__ == "__main__":
    unittest.main()

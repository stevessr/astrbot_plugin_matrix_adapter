import unittest

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

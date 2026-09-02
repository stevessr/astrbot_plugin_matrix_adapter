import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV113ReplyFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_plain_reply_does_not_copy_removed_reply_fallback(self):
        mod = load_module("sender.events.plain.core")
        message_components = __import__(
            "astrbot.api.message_components",
            fromlist=["Plain"],
        )
        sent = []

        class Client:
            user_id = "@bot:example.org"

            async def send_message(self, *, room_id, msg_type, content):
                sent.append((room_id, msg_type, content))
                return {"event_id": "$reply"}

        await mod.send_plain(
            Client(),
            message_components.Plain("new reply"),
            "!room:example.org",
            "$original",
            None,
            False,
            {
                "sender": "@alice:example.org",
                "body": "SECRET OLD BODY",
                "mentions": {"user_ids": ["@old-mention:example.org"]},
            },
            False,
            None,
            False,
        )

        content = sent[0][2]
        self.assertEqual(content["body"], "new reply")
        self.assertNotIn("SECRET OLD BODY", content.get("formatted_body", ""))
        self.assertNotIn("<mx-reply", content.get("formatted_body", ""))
        self.assertEqual(
            content["m.relates_to"],
            {"m.in_reply_to": {"event_id": "$original"}},
        )
        # v1.16/MSC4142 + intentional mentions: reply pings the target sender,
        # but does not propagate mentions from the previous message.
        self.assertEqual(
            content["m.mentions"],
            {"user_ids": ["@alice:example.org"]},
        )


class MatrixV113ErrorTests(unittest.TestCase):
    def test_user_suspended_error_helper(self):
        mod = load_module("client.base.errors")
        error = mod.MatrixAPIError(
            403,
            {"errcode": "M_USER_SUSPENDED", "error": "account suspended"},
            "account suspended",
        )
        self.assertTrue(error.is_user_suspended)
        self.assertFalse(error.is_user_limit_exceeded)


class MatrixV113RoomReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_room_report_uses_stable_endpoint(self):
        mod = load_module("client.message.receipts.events.modify")
        calls = []

        class Client(mod.MessageEventModifyMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {}

        await Client().report_room("!room:example.org", "abuse")
        self.assertEqual(calls[0][0], "POST")
        self.assertTrue(calls[0][1].endswith("/report"))
        self.assertEqual(calls[0][2]["data"], {"reason": "abuse"})


if __name__ == "__main__":
    unittest.main()

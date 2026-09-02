import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV111MathTests(unittest.IsolatedAsyncioTestCase):
    async def test_math_message_uses_stable_data_mx_maths_markup(self):
        mod = load_module("sender.sender_lib.media.operations.messages.custom")
        calls = []

        class Sender(mod.SenderMediaCustomMixin):
            use_notice = False

            async def send_custom_message(self, **kwargs):
                calls.append(kwargs)
                return {"event_id": "$math"}

        response = await Sender().send_math_message(
            "!room:example.org",
            r"x^2 < y",
            fallback="x² < y",
            block=False,
        )

        self.assertEqual(response["event_id"], "$math")
        content = calls[0]["content"]
        self.assertEqual(calls[0]["event_type"], "m.room.message")
        self.assertEqual(content["msgtype"], "m.text")
        self.assertEqual(content["body"], "x² < y")
        self.assertEqual(content["format"], "org.matrix.custom.html")
        self.assertIn("<span data-mx-maths=", content["formatted_body"])
        self.assertIn("x^2 &lt; y", content["formatted_body"])
        self.assertIn("x² &lt; y", content["formatted_body"])

    async def test_block_math_uses_div_and_notice_setting(self):
        mod = load_module("sender.sender_lib.media.operations.messages.custom")
        calls = []

        class Sender(mod.SenderMediaCustomMixin):
            use_notice = True

            async def send_custom_message(self, **kwargs):
                calls.append(kwargs)
                return {}

        await Sender().send_math_message(
            "!room:example.org",
            r"\\int_0^1 x dx",
            block=True,
        )
        content = calls[0]["content"]
        self.assertEqual(content["msgtype"], "m.notice")
        self.assertTrue(content["formatted_body"].startswith("<div data-mx-maths="))


class MatrixV111UnsignedMembershipTests(unittest.TestCase):
    def test_event_exposes_unsigned_membership(self):
        mod = load_module("client.event_types.base")
        event = mod.MatrixEvent.from_dict(
            {
                "event_id": "$event",
                "sender": "@alice:example.org",
                "origin_server_ts": 1,
                "type": "m.room.message",
                "content": {"msgtype": "m.text", "body": "hello"},
                "unsigned": {"membership": "join"},
            },
            "!room:example.org",
        )
        self.assertEqual(event.unsigned_membership, "join")


if __name__ == "__main__":
    unittest.main()

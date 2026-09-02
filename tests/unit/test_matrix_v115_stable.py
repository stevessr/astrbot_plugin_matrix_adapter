import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV115RoomSummaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_room_summary_uses_stable_v1_endpoint_and_via(self):
        mod = load_module("client.room_management_mixin.hierarchy")
        calls = []

        class Client(mod.RoomHierarchyMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {
                    "room_id": "!opaque",
                    "allowed_room_ids": ["!allowed"],
                    "encryption": "m.megolm.v1.aes-sha2",
                    "room_version": "12",
                }

        result = await Client().get_room_summary(
            "#space:example.org",
            via=["example.org", "example.org", "elsewhere.org"],
        )
        self.assertTrue(calls[0][1].startswith("/_matrix/client/v1/room_summary/"))
        self.assertEqual(
            calls[0][2]["params"]["via"],
            ["example.org", "elsewhere.org"],
        )
        self.assertEqual(result["room_version"], "12")
        self.assertEqual(result["allowed_room_ids"], ["!allowed"])


class MatrixV115RichTopicTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.topic = load_module("room_topic")

    def test_rich_topic_codec_prefers_stable_plain_and_retains_html(self):
        content = self.topic.build_room_topic_content(
            "plain topic",
            formatted_topic="<b>rich topic</b>",
        )
        self.assertEqual(content["topic"], "plain topic")
        self.assertEqual(
            content["m.topic"]["m.text"][0],
            {"mimetype": "text/html", "body": "<b>rich topic</b>"},
        )
        self.assertEqual(
            self.topic.extract_room_topic(content),
            ("plain topic", "<b>rich topic</b>"),
        )

    def test_rich_topic_falls_back_to_legacy_topic_on_malformed_block(self):
        self.assertEqual(
            self.topic.extract_room_topic(
                {"topic": "legacy", "m.topic": {"m.text": "broken"}}
            ),
            ("legacy", None),
        )

    async def test_set_room_topic_emits_stable_and_legacy_fields(self):
        mod = load_module("client.room_state.configuration.events.identity")
        calls = []

        class Client(mod.RoomStateIdentityMixin):
            async def set_room_state_event(self, **kwargs):
                calls.append(kwargs)
                return {"event_id": "$topic"}

        await Client().set_room_topic(
            "!room:example.org",
            "plain",
            formatted_topic="<em>plain</em>",
        )
        content = calls[0]["content"]
        self.assertEqual(content["topic"], "plain")
        self.assertEqual(content["m.topic"]["m.text"][0]["mimetype"], "text/html")
        self.assertEqual(content["m.topic"]["m.text"][-1]["mimetype"], "text/plain")

    def test_room_state_cache_keeps_plain_and_html_topic(self):
        room_mod = load_module("client.event_types.room")
        apply_mod = load_module("processors.event_lib.states.persistence.apply")

        class Processor(apply_mod.MatrixEventProcessorApplyMixin):
            pass

        room = room_mod.MatrixRoom("!room:example.org")
        Processor()._apply_room_state_event(
            room,
            {
                "type": "m.room.topic",
                "state_key": "",
                "content": {
                    "topic": "legacy fallback",
                    "m.topic": {
                        "m.text": [
                            {"mimetype": "text/html", "body": "<b>rich</b>"},
                            {"mimetype": "text/plain", "body": "stable plain"},
                        ]
                    },
                },
            },
        )
        self.assertEqual(room.topic, "stable plain")
        self.assertEqual(room.topic_html, "<b>rich</b>")


class MatrixV115MSC4147Tests(unittest.TestCase):
    def test_olm_envelope_includes_signed_sender_device_keys(self):
        mod = load_module("e2ee.olm.olm.messages.encryption.envelope")
        signed_device = {
            "user_id": "@alice:example.org",
            "device_id": "ALICE",
            "keys": {
                "curve25519:ALICE": "curve",
                "ed25519:ALICE": "ed",
            },
            "signatures": {
                "@alice:example.org": {"ed25519:ALICE": "sig"}
            },
        }

        class Olm(mod.OlmMachineMessageEnvelopeMixin):
            user_id = "@alice:example.org"
            device_id = "ALICE"
            ed25519_key = "ed"

            def get_device_keys(self):
                return signed_device

        envelope = Olm()._build_olm_envelope(
            {"body": "secret"},
            "@bob:example.org",
            "bob-ed",
            "m.room_key",
        )
        self.assertIs(envelope["sender_device_keys"], signed_device)
        self.assertEqual(envelope["sender_device"], "ALICE")


if __name__ == "__main__":
    unittest.main()

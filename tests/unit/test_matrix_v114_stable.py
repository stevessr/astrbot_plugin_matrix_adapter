import unittest
from types import SimpleNamespace

from test_matrix_new_spec_compat import load_module


class MatrixV114ViaTests(unittest.IsolatedAsyncioTestCase):
    async def test_join_uses_via_query_not_removed_server_name(self):
        mod = load_module("client.room_core_mixin.membership")
        calls = []

        class Client(mod.RoomMembershipMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"room_id": "!room:example.org"}

        await Client().join_room(
            "!room:example.org",
            server_name=["one.example", "one.example", "two.example"],
        )
        kwargs = calls[0][2]
        self.assertEqual(kwargs["params"], {"via": ["one.example", "two.example"]})
        self.assertEqual(kwargs["data"], {})
        self.assertNotIn("server_name", kwargs["data"])
        self.assertNotIn("server_name", kwargs["params"])

    async def test_explicit_via_takes_precedence_over_compat_alias(self):
        mod = load_module("client.room_core_mixin.membership")
        calls = []

        class Client(mod.RoomMembershipMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append(kwargs)
                return {"room_id": "!room:example.org"}

        await Client().join_room(
            "#alias:example.org",
            server_name=["legacy.example"],
            via=["stable.example"],
        )
        self.assertEqual(calls[0]["params"], {"via": ["stable.example"]})

    async def test_knock_uses_via_query_and_reason_body(self):
        mod = load_module("client.room_management_mixin.lifecycle.knock")
        calls = []

        class Client(mod.RoomKnockMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"room_id": "!room:example.org"}

        await Client().knock_room(
            "!room:example.org",
            reason="please",
            via=["one.example", "one.example", "two.example"],
        )
        kwargs = calls[0][2]
        self.assertEqual(kwargs["params"], {"via": ["one.example", "two.example"]})
        self.assertEqual(kwargs["data"], {"reason": "please"})


class MatrixV114UserReportingTests(unittest.IsolatedAsyncioTestCase):
    async def test_user_report_uses_stable_v3_endpoint(self):
        mod = load_module("client.message.receipts.events.modify")
        calls = []

        class Client(mod.MessageEventModifyMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {}

        await Client().report_user("@abuse:example.org", "spam")
        self.assertEqual(calls[0][0], "POST")
        self.assertIn("/_matrix/client/v3/users/", calls[0][1])
        self.assertTrue(calls[0][1].endswith("/report"))
        self.assertEqual(calls[0][2]["data"], {"reason": "spam"})


class MatrixV114RedactionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("processors.event_lib.room.events.redaction")

    def test_redacts_is_read_from_both_room_version_shapes(self):
        mixin = self.mod.MatrixEventProcessorRoomRedactionMixin
        self.assertEqual(
            mixin._redaction_target_id(
                {"type": "m.room.redaction", "redacts": "$old"},
                {},
            ),
            "$old",
        )
        self.assertEqual(
            mixin._redaction_target_id(
                {"type": "m.room.redaction"},
                {"redacts": "$new"},
            ),
            "$new",
        )

    async def test_current_redacted_state_is_reapplied_from_server(self):
        target = {
            "event_id": "$topic",
            "room_id": "!room:example.org",
            "type": "m.room.topic",
            "state_key": "",
            "content": {},
        }

        class Client:
            async def get_event(self, room_id, event_id):
                return dict(target)

            async def get_room_state_event(
                self, room_id, event_type, state_key="", format=None
            ):
                self.last_format = format
                return dict(target)

        class Processor(self.mod.MatrixEventProcessorRoomRedactionMixin):
            def __init__(self):
                self.client = Client()
                self.applied = []
                self.persisted = 0

            def _apply_room_state_event(self, room, event_data):
                self.applied.append(event_data)
                room.topic = event_data.get("content", {}).get("topic", "") or ""

            async def _persist_room_state(self, room):
                self.persisted += 1

        room = SimpleNamespace(room_id="!room:example.org", topic="old topic")
        processor = Processor()
        await processor._refresh_redacted_current_state(room, "$topic")
        self.assertEqual(processor.client.last_format, "event")
        self.assertEqual(room.topic, "")
        self.assertEqual(processor.persisted, 1)
        self.assertEqual(processor.applied[0]["event_id"], "$topic")

    async def test_old_redacted_state_does_not_replace_new_current_state(self):
        target = {
            "event_id": "$old-topic",
            "room_id": "!room:example.org",
            "type": "m.room.topic",
            "state_key": "",
            "content": {},
        }

        class Client:
            async def get_event(self, room_id, event_id):
                return dict(target)

            async def get_room_state_event(self, *args, **kwargs):
                return {
                    "event_id": "$new-topic",
                    "type": "m.room.topic",
                    "state_key": "",
                    "content": {"topic": "new"},
                }

        class Processor(self.mod.MatrixEventProcessorRoomRedactionMixin):
            def __init__(self):
                self.client = Client()
                self.applied = []

            def _apply_room_state_event(self, room, event_data):
                self.applied.append(event_data)

            async def _persist_room_state(self, room):
                raise AssertionError("old state must not be persisted")

        processor = Processor()
        await processor._refresh_redacted_current_state(
            SimpleNamespace(room_id="!room:example.org"),
            "$old-topic",
        )
        self.assertEqual(processor.applied, [])


if __name__ == "__main__":
    unittest.main()

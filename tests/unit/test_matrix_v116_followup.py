import asyncio
import unittest
from collections import OrderedDict
from types import SimpleNamespace

from test_matrix_new_spec_compat import load_module


class MatrixV116ReplacementAggregationTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_module("client.event_types.parser.core")

    def test_bundled_latest_replacement_is_applied(self):
        original_relation = {
            "rel_type": "m.thread",
            "event_id": "$root",
        }
        raw = {
            "event_id": "$original",
            "sender": "@alice:example.org",
            "type": "m.room.message",
            "content": {
                "body": "old",
                "msgtype": "m.text",
                "m.relates_to": original_relation,
            },
            "unsigned": {
                "m.relations": {
                    "m.replace": {
                        "event_id": "$edit",
                        "origin_server_ts": 200,
                        "sender": "@alice:example.org",
                        "type": "m.room.message",
                        "content": {
                            "body": "* new",
                            "msgtype": "m.text",
                            "m.new_content": {
                                "body": "new",
                                "msgtype": "m.text",
                                "m.relates_to": {
                                    "rel_type": "m.reference",
                                    "event_id": "$must-be-ignored",
                                },
                            },
                            "m.relates_to": {
                                "rel_type": "m.replace",
                                "event_id": "$original",
                            },
                        },
                    }
                }
            },
        }

        normalized = self.mod._apply_bundled_replacement(raw)
        self.assertEqual(normalized["content"]["body"], "new")
        self.assertEqual(normalized["content"]["m.relates_to"], original_relation)
        self.assertEqual(raw["content"]["body"], "old")

    def test_invalid_bundled_replacement_is_ignored(self):
        raw = {
            "event_id": "$original",
            "sender": "@alice:example.org",
            "type": "m.room.message",
            "content": {"body": "old", "msgtype": "m.text"},
            "unsigned": {
                "m.relations": {
                    "m.replace": {
                        "event_id": "$edit",
                        "origin_server_ts": 999,
                        "sender": "@mallory:example.org",
                        "type": "m.room.message",
                        "content": {
                            "m.new_content": {"body": "pwned", "msgtype": "m.text"},
                            "m.relates_to": {
                                "rel_type": "m.replace",
                                "event_id": "$original",
                            },
                        },
                    }
                }
            },
        }
        self.assertIs(self.mod._apply_bundled_replacement(raw), raw)
        self.assertEqual(raw["content"]["body"], "old")


class MatrixV116ReplacementOrderingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("processors.event_lib.msg.dispatch.edit")

    @staticmethod
    def _event(event_id: str, ts: int, *, sender="@alice:example.org"):
        return SimpleNamespace(
            room_id="!room:example.org",
            event_id=event_id,
            origin_server_ts=ts,
            sender=sender,
            event_type="m.room.message",
            body="* edited",
            msgtype="m.text",
        )

    @staticmethod
    def _content(body: str = "edited"):
        return {
            "body": f"* {body}",
            "msgtype": "m.text",
            "m.new_content": {"body": body, "msgtype": "m.text"},
            "m.relates_to": {"rel_type": "m.replace", "event_id": "$original"},
        }

    def _processor(self, target_sender="@alice:example.org"):
        mod = self.mod

        class Client:
            async def get_event(self, room_id, event_id):
                return {
                    "room_id": room_id,
                    "event_id": event_id,
                    "sender": target_sender,
                    "type": "m.room.message",
                    "content": {"body": "original", "msgtype": "m.text"},
                }

        class Processor(mod.MatrixEventProcessorMessagesEditMixin):
            def __init__(self):
                self.client = Client()
                self._latest_replacements = OrderedDict()
                self._max_processed_messages = 1000

        return Processor()

    async def test_older_edit_is_suppressed_after_newer_edit(self):
        processor = self._processor()
        newer = self._event("$z", 200)
        older = self._event("$y", 100)

        self.assertFalse(await processor._normalize_message_edit(newer, self._content("new")))
        self.assertTrue(await processor._normalize_message_edit(older, self._content("old")))

    async def test_equal_timestamp_uses_lexicographically_largest_event_id(self):
        processor = self._processor()
        first = self._event("$a", 200)
        later = self._event("$b", 200)
        stale = self._event("$aa", 200)

        self.assertFalse(await processor._normalize_message_edit(first, self._content("a")))
        self.assertFalse(await processor._normalize_message_edit(later, self._content("b")))
        self.assertTrue(await processor._normalize_message_edit(stale, self._content("aa")))

    async def test_invalid_high_timestamp_edit_does_not_poison_order_cache(self):
        processor = self._processor(target_sender="@alice:example.org")
        invalid = self._event("$evil", 999, sender="@mallory:example.org")
        valid = self._event("$good", 100, sender="@alice:example.org")

        self.assertTrue(await processor._normalize_message_edit(invalid, self._content("evil")))
        self.assertEqual(processor._latest_replacements, OrderedDict())
        self.assertFalse(await processor._normalize_message_edit(valid, self._content("good")))


class MatrixV116MSC4311StrippedStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_invite_and_knock_create_state_is_passed_through_unchanged(self):
        invite_mod = load_module("sync.sync_lib.dispatch.routing.rooms.invite")
        knock_mod = load_module("sync.sync_lib.dispatch.routing.rooms.knock")
        received = []

        class Router(
            invite_mod.MatrixSyncManagerEventRoutingRoomsInviteMixin,
            knock_mod.MatrixSyncManagerEventRoutingRoomsKnockMixin,
        ):
            def __init__(self):
                self.on_invite = self._on_invite
                self.on_knock = self._on_knock

            async def _run_callback_with_guard(self, _name, callback, *args):
                await callback(*args)

            async def _on_invite(self, room_id, data):
                received.append(("invite", room_id, data))

            async def _on_knock(self, room_id, data):
                received.append(("knock", room_id, data))

        create_state = {
            "type": "m.room.create",
            "sender": "@creator:origin.example",
            "state_key": "",
            "content": {"room_version": "12"},
        }
        invite_data = {"invite_state": {"events": [create_state]}}
        knock_data = {"knock_state": {"events": [create_state]}}
        tasks = []
        router = Router()
        router._dispatch_invite_room_fields({"!opaque": invite_data}, tasks)
        router._dispatch_knock_room_fields({"!opaque": knock_data}, tasks)
        await asyncio.gather(*tasks)

        self.assertEqual(received[0][2]["invite_state"]["events"][0], create_state)
        self.assertEqual(received[1][2]["knock_state"]["events"][0], create_state)


if __name__ == "__main__":
    unittest.main()

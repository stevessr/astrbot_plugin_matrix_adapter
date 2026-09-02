import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV116ProfileCapabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.auth.discovery.capabilities")

    async def test_profile_allowed_list_is_enforced(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                if endpoint.endswith("/capabilities"):
                    return {
                        "capabilities": {
                            "m.profile_fields": {
                                "enabled": True,
                                "allowed": ["m.tz", "org.example.title"],
                            }
                        }
                    }
                raise AssertionError(endpoint)

        client = Client()
        self.assertTrue(await client.can_set_profile_field("m.tz"))
        self.assertFalse(await client.can_set_profile_field("org.example.blocked"))

    async def test_absent_profile_capability_in_v116_defaults_supported(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                if endpoint.endswith("/capabilities"):
                    return {"capabilities": {}}
                if endpoint.endswith("/versions"):
                    return {"versions": ["r0.6.1", "v1.16"]}
                raise AssertionError(endpoint)

        self.assertTrue(await Client().can_set_profile_field("org.example.custom"))

    async def test_absent_profile_capability_on_old_server_is_unknown(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                if endpoint.endswith("/capabilities"):
                    return {"capabilities": {}}
                if endpoint.endswith("/versions"):
                    return {"versions": ["v1.15"]}
                raise AssertionError(endpoint)

        self.assertIsNone(await Client().can_set_profile_field("org.example.custom"))


class MatrixV116ExtendedProfileTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.profile.extended.basic.extended")

    async def test_timezone_uses_stable_profile_endpoint_and_key(self):
        calls = []

        class Client(self.mod.ProfileExtendedFieldsMixin):
            user_id = "@bot:example.org"

            async def _request(self, method, endpoint, data=None, **kwargs):
                calls.append((method, endpoint, data, kwargs))
                if method == "GET":
                    return {"m.tz": "Asia/Tokyo"}
                return {}

        client = Client()
        await client.set_profile_timezone("Asia/Tokyo")
        self.assertEqual(calls[0][0], "PUT")
        self.assertIn("/_matrix/client/v3/profile/", calls[0][1])
        self.assertTrue(calls[0][1].endswith("/m.tz"))
        self.assertEqual(calls[0][2], {"m.tz": "Asia/Tokyo"})

        self.assertEqual(await client.get_profile_timezone(), "Asia/Tokyo")
        self.assertEqual(calls[1][0], "GET")
        self.assertTrue(calls[1][1].endswith("/m.tz"))

    async def test_stable_permission_error_does_not_fallback_to_unstable(self):
        calls = []
        errors = load_module("client.base.errors")

        class Client(self.mod.ProfileExtendedFieldsMixin):
            user_id = "@bot:example.org"

            async def _request(self, method, endpoint, data=None, **kwargs):
                calls.append(endpoint)
                raise errors.MatrixAPIError(
                    403,
                    {"errcode": "M_FORBIDDEN", "error": "managed field"},
                    "managed field",
                )

        with self.assertRaises(errors.MatrixAPIError):
            await Client().set_extended_profile_field("org.example.managed", "x")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("/_matrix/client/v3/profile/"))


class MatrixV116StateEventFormatTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.room_core_mixin.state")

    async def test_state_event_format_event_is_sent_as_query(self):
        calls = []

        class Client(self.mod.RoomCoreStateMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"event_id": "$state:example.org"}

        result = await Client().get_room_state_event(
            "!room:example.org",
            "m.room.name",
            "",
            format="event",
        )
        self.assertEqual(result["event_id"], "$state:example.org")
        self.assertEqual(calls[0][2]["params"], {"format": "event"})

    async def test_invalid_state_event_format_is_rejected(self):
        class Client(self.mod.RoomCoreStateMixin):
            async def _request(self, *args, **kwargs):
                raise AssertionError("network should not be reached")

        with self.assertRaises(ValueError):
            await Client().get_room_state_event(
                "!room:example.org", "m.room.name", format="full"
            )


class MatrixV116SyncStateAfterTests(unittest.IsolatedAsyncioTestCase):
    async def test_sync_requests_stable_state_after(self):
        mod = load_module("client.auth.sync.polling")
        calls = []

        class Client(mod.AuthSyncPollingMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"next_batch": "n", "rooms": {}}

        await Client().sync(timeout=1000, use_state_after=True)
        self.assertEqual(calls[0][2]["params"]["use_state_after"], "true")

    async def test_state_after_is_authoritative_over_timeline_state(self):
        mod = load_module("processors.event_lib.room.dispatch.core")
        state_batches = []
        timeline_seen = []

        class Processor(mod.MatrixEventProcessorRoomDispatchCoreMixin):
            global_account_data = {}
            e2ee_manager = None

            async def _load_room_members(self, room_id, room, room_data):
                return True

            async def _process_room_state_events(self, room, events, e2ee_manager):
                state_batches.append(list(events))

            async def _persist_room_state(self, room):
                return None

            async def _handle_event(self, room, event_data):
                timeline_seen.append(event_data.get("event_id"))

        await Processor().process_room_events(
            "!room:example.org",
            {
                "state_after": {
                    "events": [
                        {
                            "type": "m.room.topic",
                            "state_key": "",
                            "event_id": "$authoritative",
                            "content": {"topic": "current"},
                        }
                    ]
                },
                "timeline": {
                    "events": [
                        {
                            "type": "m.room.topic",
                            "state_key": "",
                            "event_id": "$stale",
                            "content": {"topic": "loser"},
                        },
                        {
                            "type": "m.room.message",
                            "event_id": "$message",
                            "content": {"msgtype": "m.text", "body": "hi"},
                        },
                    ]
                },
            },
        )
        self.assertEqual(state_batches[0][0]["event_id"], "$authoritative")
        self.assertEqual(timeline_seen, ["$message"])


class MatrixV116ReplyMentionTests(unittest.TestCase):
    def test_reply_does_not_propagate_mentions_from_previous_message(self):
        mod = load_module("sender.events.plain.mentions")

        class Client:
            user_id = "@bot:example.org"

        content = {
            "m.mentions": {"user_ids": ["@explicit:example.org"]},
        }
        mod._merge_reply_mentions(
            content,
            Client(),
            {
                "sender": "@sender:example.org",
                "mentions": {
                    "user_ids": ["@old-ping:example.org"],
                    "room": True,
                },
            },
        )
        self.assertEqual(
            content["m.mentions"]["user_ids"],
            ["@sender:example.org", "@explicit:example.org"],
        )
        self.assertNotIn("@old-ping:example.org", content["m.mentions"]["user_ids"])
        self.assertNotIn("room", content["m.mentions"])


class MatrixV116RoomV12Tests(unittest.IsolatedAsyncioTestCase):
    async def test_upgrade_sends_full_additional_creator_set(self):
        mod = load_module("client.room_management_mixin.lifecycle.transition")
        calls = []

        class Client(mod.RoomTransitionMixin):
            async def _request(self, method, endpoint, data=None, **kwargs):
                calls.append((method, endpoint, data))
                return {"replacement_room": "!new"}

        await Client().upgrade_room(
            "!old:example.org",
            "12",
            additional_creators=["@alice:example.org", "@alice:example.org"],
        )
        self.assertEqual(
            calls[0][2],
            {
                "new_version": "12",
                "additional_creators": ["@alice:example.org"],
            },
        )

    def test_create_room_exposes_room_version_and_additional_creators(self):
        mod = load_module("client.user.rooms.creation.general")
        client = mod.UserRoomCreationGeneralMixin()
        data = client._build_create_room_data(
            "Room",
            None,
            ["@invitee:example.org"],
            False,
            "trusted_private_chat",
            {"m.federate": True},
            None,
            "12",
            ["@creator:example.org"],
        )
        self.assertEqual(data["room_version"], "12")
        self.assertEqual(
            data["creation_content"]["additional_creators"],
            ["@creator:example.org"],
        )
        self.assertTrue(data["creation_content"]["m.federate"])


if __name__ == "__main__":
    unittest.main()

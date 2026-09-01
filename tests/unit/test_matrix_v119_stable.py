import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV119MutualRoomsTests(unittest.IsolatedAsyncioTestCase):
    async def test_mutual_rooms_uses_stable_v1_endpoint_and_pagination(self):
        mod = load_module("client.user.rooms.mutual")
        calls = []

        class Client(mod.UserMutualRoomsMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {
                    "joined": ["!b:example.org", "!a:example.org"],
                    "next_batch": "n",
                }

        result = await Client().get_mutual_rooms(" @alice:example.org ", " page-1 ")
        self.assertEqual(result["next_batch"], "n")
        self.assertEqual(
            calls[0],
            (
                "GET",
                "/_matrix/client/v1/mutual_rooms",
                {"params": {"user_id": "@alice:example.org", "from": "page-1"}},
            ),
        )


class MatrixV119RoomDirectoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_room_order_is_left_server_defined(self):
        mod = load_module("client.room_directory_mixin.public")
        server_response = {
            "chunk": [
                {"room_id": "!small:example.org", "num_joined_members": 2},
                {"room_id": "!large:example.org", "num_joined_members": 500},
            ]
        }

        class Client(mod.RoomPublicDirectoryMixin):
            async def _request(self, method, endpoint, **kwargs):
                return server_response

        result = await Client().list_public_rooms()
        self.assertIs(result, server_response)
        self.assertEqual(
            [room["room_id"] for room in result["chunk"]],
            ["!small:example.org", "!large:example.org"],
        )


class MatrixV119KeyBackupTests(unittest.IsolatedAsyncioTestCase):
    async def test_key_backup_account_preference_round_trip(self):
        mod = load_module("client.key_backup_mixin.preference")
        state = {"enabled": True}

        class Client(mod.KeyBackupPreferenceMixin):
            async def get_global_account_data(self, event_type):
                self.read_type = event_type
                return dict(state)

            async def set_global_account_data(self, event_type, content):
                self.write = (event_type, content)
                state.clear()
                state.update(content)
                return {}

        client = Client()
        self.assertTrue(await client.get_key_backup_preference())
        await client.set_key_backup_preference(False)
        self.assertEqual(client.read_type, "m.key_backup")
        self.assertEqual(client.write, ("m.key_backup", {"enabled": False}))
        self.assertFalse(await client.get_key_backup_preference())


class MatrixV119StateReplacementTests(unittest.TestCase):
    def test_unsigned_replaces_state_is_exposed(self):
        mod = load_module("client.event_types.base")
        event = mod.MatrixEvent.from_dict(
            {
                "event_id": "$new:example.org",
                "sender": "@alice:example.org",
                "type": "m.room.name",
                "content": {"name": "new"},
                "unsigned": {"replaces_state": "$old:example.org"},
            },
            "!room:example.org",
        )
        self.assertEqual(event.replaces_state, "$old:example.org")


class MatrixV119ImagePackTests(unittest.TestCase):
    def test_stable_image_pack_event_types_are_primary(self):
        mod = load_module("sticker.syncer.state")
        self.assertEqual(
            mod.StickerSyncStateMixin.ROOM_IMAGE_PACK_TYPE,
            "m.room.image_pack",
        )
        self.assertEqual(
            mod.StickerSyncStateMixin.USER_IMAGE_PACK_ROOMS_TYPE,
            "m.image_pack.rooms",
        )
        self.assertIn(
            "m.room.image_pack",
            mod.StickerSyncStateMixin.ROOM_PACK_TYPES,
        )


class MatrixV119MXCGrammarTests(unittest.TestCase):
    def test_utils_parser_accepts_only_stable_media_id_characters(self):
        mod = load_module("utils.utils_lib.media.urls")
        parser = mod.MatrixUtilsMediaUrlMixin._parse_mxc_url
        self.assertEqual(
            parser("mxc://example.org/AbC_123-xyz"),
            ("example.org", "AbC_123-xyz"),
        )
        self.assertIsNone(parser("mxc://example.org/../secret"))
        self.assertIsNone(parser("mxc://example.org/a%2Fb"))
        self.assertIsNone(parser("mxc://example.org/a/b"))

    def test_repository_parser_rejects_invalid_media_id(self):
        mod = load_module("client.media.misc.repository")
        parse = mod.MediaRepositoryMixin._parse_mxc_server_media_id
        self.assertEqual(
            parse("mxc://example.org/media_123-ABC"),
            ("example.org", "media_123-ABC"),
        )
        with self.assertRaises(ValueError):
            parse("mxc://example.org/../../etc-passwd")


if __name__ == "__main__":
    unittest.main()

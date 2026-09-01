import base64
import hashlib
import unittest

from test_matrix_new_spec_compat import load_module


def _b64(value: bytes, *, urlsafe: bool = False) -> str:
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(value).decode("ascii").rstrip("=")


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


class MatrixV119ContextPaginationTests(unittest.IsolatedAsyncioTestCase):
    async def test_context_start_paginates_backwards_and_end_forwards(self):
        mod = load_module("sender.core.moderation")
        calls = []

        class Client:
            async def room_messages(self, **kwargs):
                calls.append(kwargs)
                return {"chunk": []}

        class Sender(mod.SenderModerationMixin):
            client = Client()

        sender = Sender()
        context = {"start": "before-token", "end": "after-token"}
        await sender.paginate_message_context(
            "!room:example.org", context, direction="b", limit=7
        )
        await sender.paginate_message_context(
            "!room:example.org", context, direction="f", limit=8
        )
        self.assertEqual(
            calls[0],
            {
                "room_id": "!room:example.org",
                "from_token": "before-token",
                "direction": "b",
                "limit": 7,
            },
        )
        self.assertEqual(
            calls[1],
            {
                "room_id": "!room:example.org",
                "from_token": "after-token",
                "direction": "f",
                "limit": 8,
            },
        )

    async def test_context_pagination_rejects_missing_direction_token(self):
        mod = load_module("sender.core.moderation")

        class Sender(mod.SenderModerationMixin):
            client = object()

        with self.assertRaisesRegex(ValueError, "end"):
            await Sender().paginate_message_context(
                "!room:example.org", {"start": "before"}, direction="f"
            )


class MatrixV119UpgradeViaTests(unittest.IsolatedAsyncioTestCase):
    async def test_sender_preserves_explicit_remote_join_servers(self):
        mod = load_module("sender.sender_lib.room.operations.lifecycle")
        calls = []

        class Client:
            async def join_room(self, room_id, server_name=None):
                calls.append((room_id, server_name))
                return {"room_id": room_id}

        class Sender(mod.SenderRoomLifecycleMixin):
            client = Client()

        await Sender().join_room(
            "!remote:elsewhere.example",
            server_name=["elsewhere.example", "backup.example"],
        )
        self.assertEqual(
            calls[-1],
            (
                "!remote:elsewhere.example",
                ["elsewhere.example", "backup.example"],
            ),
        )

    async def test_upgrade_reference_uses_event_sender_server_as_via(self):
        mod = load_module("sender.sender_lib.room.operations.lifecycle")
        calls = []

        class Client:
            async def join_room(self, room_id, server_name=None):
                calls.append((room_id, server_name))
                return {"room_id": room_id}

        class Sender(mod.SenderRoomLifecycleMixin):
            client = Client()

        await Sender().join_room_from_upgrade_reference(
            "!new:remote.example",
            "@upgrader:via.example:8448",
        )
        self.assertEqual(
            calls[-1],
            ("!new:remote.example", ["via.example:8448"]),
        )


class MatrixV119RoomMessageTests(unittest.IsolatedAsyncioTestCase):
    async def test_room_messages_preserve_encrypted_events(self):
        mod = load_module("client.room_core_mixin.messages")
        encrypted_event = {
            "event_id": "$encrypted:example.org",
            "type": "m.room.encrypted",
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "ciphertext": "opaque",
                "session_id": "session",
                "sender_key": "curve25519",
            },
        }
        response = {"chunk": [encrypted_event], "end": "next"}

        class Client(mod.RoomMessageHistoryMixin):
            async def _request(self, method, endpoint, **kwargs):
                return response

        result = await Client().room_messages("!room:example.org")
        self.assertIs(result, response)
        self.assertEqual(result["chunk"][0]["type"], "m.room.encrypted")
        self.assertEqual(result["chunk"][0]["content"]["ciphertext"], "opaque")


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


class MatrixV119EncryptedFileTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_module("utils.media_crypto")
        self.ciphertext = b"encrypted attachment bytes"
        self.file_info = {
            "url": "mxc://example.org/media_123",
            "key": {
                "kty": "oct",
                "key_ops": ["encrypt", "decrypt"],
                "alg": "A256CTR",
                "k": _b64(b"k" * 32, urlsafe=True),
                "ext": True,
            },
            "iv": _b64(b"i" * 16),
            "hashes": {"sha256": _b64(hashlib.sha256(self.ciphertext).digest())},
            "v": "v2",
        }

    def test_stable_encrypted_file_metadata_is_accepted(self):
        key, iv, digest = self.mod._validate_encrypted_file_info(self.file_info)
        self.assertEqual(key, b"k" * 32)
        self.assertEqual(iv, b"i" * 16)
        self.assertEqual(digest, hashlib.sha256(self.ciphertext).digest())

    def test_sha256_is_required(self):
        invalid = {**self.file_info, "hashes": {}}
        with self.assertRaisesRegex(ValueError, "hashes.sha256"):
            self.mod._validate_encrypted_file_info(invalid)

    def test_jwk_algorithm_contract_is_required(self):
        invalid = {
            **self.file_info,
            "key": {**self.file_info["key"], "alg": "A128CTR"},
        }
        with self.assertRaisesRegex(ValueError, "A256CTR"):
            self.mod._validate_encrypted_file_info(invalid)

    def test_ciphertext_hash_mismatch_is_rejected_before_decryption(self):
        invalid = {
            **self.file_info,
            "hashes": {"sha256": _b64(b"x" * 32)},
        }
        with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
            self.mod.decrypt_encrypted_file(invalid, self.ciphertext)


if __name__ == "__main__":
    unittest.main()

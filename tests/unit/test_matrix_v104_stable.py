import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV104PublicRoomsTests(unittest.IsolatedAsyncioTestCase):
    async def test_filtered_remote_public_rooms_keeps_server_in_query(self):
        mod = load_module("client.room_directory_mixin.public")
        calls = []

        class Client(mod.RoomPublicDirectoryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().list_public_rooms(
            server="remote.example",
            limit=20,
            filter={"generic_search_term": "matrix"},
            room_types=[None, "m.space"],
        )

        method, endpoint, kwargs = calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(endpoint, "/_matrix/client/v3/publicRooms")
        self.assertEqual(kwargs["params"], {"server": "remote.example"})
        self.assertNotIn("server", kwargs["data"])
        self.assertEqual(kwargs["data"]["limit"], 20)
        self.assertEqual(
            kwargs["data"]["filter"],
            {"generic_search_term": "matrix", "room_types": [None, "m.space"]},
        )

    async def test_room_types_selects_post_and_allows_untyped_rooms(self):
        mod = load_module("client.room_directory_mixin.public")
        calls = []

        class Client(mod.RoomPublicDirectoryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().list_public_rooms(room_types=[None])
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][2]["data"]["filter"]["room_types"], [None])

    async def test_unfiltered_listing_stays_get(self):
        mod = load_module("client.room_directory_mixin.public")
        calls = []

        class Client(mod.RoomPublicDirectoryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().list_public_rooms(server="example.org", limit=5)
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(
            calls[0][2]["params"], {"server": "example.org", "limit": 5}
        )


if __name__ == "__main__":
    unittest.main()

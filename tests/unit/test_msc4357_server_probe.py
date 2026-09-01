import types
import unittest
from unittest import mock

from test_matrix_new_spec_compat import load_module


class MatrixMSC4357ServerProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.state_mod = load_module("client.room_core_mixin.state")
        self.dispatch_mod = load_module("adapter.message.handler.callback.dispatch")

    def _missing(self):
        return self.state_mod.MatrixAPIError(
            404,
            {"errcode": "M_NOT_FOUND", "error": "State event not found"},
            "missing",
        )

    def _make_state_probe(self, responses):
        state_mod = self.state_mod

        class Probe(state_mod.RoomCoreStateMixin):
            def __init__(self):
                self.calls = []

            async def get_room_state_event(
                self, room_id: str, event_type: str, state_key: str = ""
            ):
                self.calls.append((room_id, event_type, state_key))
                value = responses[event_type]
                if isinstance(value, BaseException):
                    raise value
                return value

        return Probe()

    async def test_stable_room_policy_takes_precedence(self):
        probe = self._make_state_probe(
            {
                self.state_mod.M_ROOM_LIVE_MESSAGING: {"enabled": False},
                self.state_mod.MSC4357_LIVE_MESSAGING_STATE: {"enabled": True},
            }
        )

        allowed = await probe.get_room_live_messaging_allowed("!room:example.org")

        self.assertFalse(allowed)
        self.assertEqual(len(probe.calls), 1)

    async def test_unstable_policy_is_used_when_stable_state_is_absent(self):
        probe = self._make_state_probe(
            {
                self.state_mod.M_ROOM_LIVE_MESSAGING: self._missing(),
                self.state_mod.MSC4357_LIVE_MESSAGING_STATE: {"enabled": False},
            }
        )

        allowed = await probe.get_room_live_messaging_allowed("!room:example.org")

        self.assertFalse(allowed)
        self.assertEqual(len(probe.calls), 2)

    async def test_absent_policy_defaults_to_enabled(self):
        probe = self._make_state_probe(
            {
                self.state_mod.M_ROOM_LIVE_MESSAGING: self._missing(),
                self.state_mod.MSC4357_LIVE_MESSAGING_STATE: self._missing(),
            }
        )

        self.assertTrue(
            await probe.get_room_live_messaging_allowed("!room:example.org")
        )

    async def test_non_404_probe_failure_is_not_treated_as_absent(self):
        failure = self.state_mod.MatrixAPIError(
            403,
            {"errcode": "M_FORBIDDEN", "error": "Forbidden"},
            "forbidden",
        )
        probe = self._make_state_probe(
            {
                self.state_mod.M_ROOM_LIVE_MESSAGING: failure,
                self.state_mod.MSC4357_LIVE_MESSAGING_STATE: {"enabled": True},
            }
        )

        with self.assertRaises(self.state_mod.MatrixAPIError):
            await probe.get_room_live_messaging_allowed("!room:example.org")

    async def test_dispatch_probes_once_then_uses_room_cache(self):
        client = types.SimpleNamespace(
            get_room_live_messaging_allowed=mock.AsyncMock(return_value=True)
        )
        adapter = types.SimpleNamespace(client=client)
        room = types.SimpleNamespace(
            room_id="!room:example.org",
            live_messaging_enabled=None,
            live_messaging_policy_probed=False,
        )

        first = await self.dispatch_mod._resolve_room_live_messaging_allowed(
            adapter, room
        )
        second = await self.dispatch_mod._resolve_room_live_messaging_allowed(
            adapter, room
        )

        self.assertTrue(first)
        self.assertTrue(second)
        client.get_room_live_messaging_allowed.assert_awaited_once_with(
            "!room:example.org"
        )
        self.assertTrue(room.live_messaging_policy_probed)
        self.assertTrue(room.live_messaging_enabled)

    async def test_dispatch_probe_failure_falls_back_without_poisoning_cache(self):
        client = types.SimpleNamespace(
            get_room_live_messaging_allowed=mock.AsyncMock(
                side_effect=RuntimeError("temporary failure")
            )
        )
        adapter = types.SimpleNamespace(client=client)
        room = types.SimpleNamespace(
            room_id="!room:example.org",
            live_messaging_enabled=None,
            live_messaging_policy_probed=False,
        )

        allowed = await self.dispatch_mod._resolve_room_live_messaging_allowed(
            adapter, room
        )

        self.assertFalse(allowed)
        self.assertFalse(room.live_messaging_policy_probed)
        self.assertIsNone(room.live_messaging_enabled)


class MatrixMSC4357VersionsAdvertisementTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cap_mod = load_module("client.auth.discovery.capabilities")

    def _make_probe(self, payload):
        cap_mod = self.cap_mod

        class Probe(cap_mod.AuthDiscoveryCapabilitiesMixin):
            async def get_versions(self):
                return payload

        return Probe()

    async def test_versions_positive_advertisement_is_recognized(self):
        probe = self._make_probe(
            {"unstable_features": {"org.matrix.msc4357": True}}
        )
        self.assertTrue(await probe.get_msc4357_server_advertisement())

    async def test_versions_explicit_negative_advertisement_is_recognized(self):
        probe = self._make_probe(
            {"unstable_features": {"org.matrix.msc4357": False}}
        )
        self.assertFalse(await probe.get_msc4357_server_advertisement())

    async def test_missing_versions_flag_is_unknown_not_unsupported(self):
        probe = self._make_probe({"unstable_features": {}})
        self.assertIsNone(await probe.get_msc4357_server_advertisement())

    async def test_stable_advertisement_hint_takes_precedence(self):
        probe = self._make_probe(
            {
                "unstable_features": {
                    "org.matrix.msc4357": False,
                    "org.matrix.msc4357.stable": True,
                }
            }
        )
        self.assertTrue(await probe.get_msc4357_server_advertisement())


if __name__ == "__main__":
    unittest.main()

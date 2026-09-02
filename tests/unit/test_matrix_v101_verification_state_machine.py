import unittest
from unittest import mock

from test_matrix_new_spec_compat import load_module


class MatrixV101TransactionReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_request_does_not_replace_existing_session(self):
        request_mod = load_module("e2ee.verification.flow_start.request.core")
        handler = request_mod.SASVerificationFlowRequestCoreMixin()
        original = {
            "sender": "@alice:example.org",
            "from_device": "ALICE1",
            "state": "accepted",
            "fingerprint": "original-fingerprint",
        }
        handler._sessions = {"txn": original}
        handler._mask_identifier = lambda value: str(value)
        handler._mask_txn_id = lambda value: str(value)
        handler._query_request_verification_keys = mock.AsyncMock()
        handler._dispatch_verification_mode = mock.AsyncMock()

        with mock.patch.object(request_mod.time, "time", return_value=1000.0):
            await handler._handle_request(
                "@mallory:example.org",
                {
                    "from_device": "MALLORY1",
                    "methods": ["m.sas.v1"],
                    "timestamp": 1000000,
                },
                "txn",
            )

        self.assertIs(handler._sessions["txn"], original)
        self.assertEqual(handler._sessions["txn"]["state"], "accepted")
        self.assertEqual(
            handler._sessions["txn"]["fingerprint"], "original-fingerprint"
        )
        handler._query_request_verification_keys.assert_not_awaited()
        handler._dispatch_verification_mode.assert_not_awaited()


class MatrixV101ToDeviceDispatchGuardTests(unittest.IsolatedAsyncioTestCase):
    def _make_handler(self):
        dispatch_mod = load_module("e2ee.verification.event.dispatch")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            dispatch_mod.SASVerificationEventDispatchMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = Harness()
        handler._sessions = {}
        handler._mask_identifier = lambda value: str(value)
        handler._mask_txn_id = lambda value: str(value)
        for name in (
            "_handle_request",
            "_handle_ready",
            "_handle_start",
            "_handle_accept",
            "_handle_key",
            "_handle_mac",
            "_handle_done",
            "_handle_cancel",
        ):
            setattr(handler, name, mock.AsyncMock())
        return handler, dispatch_mod

    async def test_legacy_standalone_start_is_delegated_for_compatibility(self):
        handler, dispatch_mod = self._make_handler()
        handled = await handler.handle_verification_event(
            dispatch_mod.M_KEY_VERIFICATION_START,
            "@alice:example.org",
            {
                "transaction_id": "legacy",
                "from_device": "ALICE1",
                "method": "m.sas.v1",
            },
        )

        self.assertTrue(handled)
        handler._handle_start.assert_awaited_once()
        self.assertEqual(handler._sessions, {})

    async def test_other_orphan_followup_events_do_not_create_flow(self):
        handler, dispatch_mod = self._make_handler()
        handled = await handler.handle_verification_event(
            dispatch_mod.M_KEY_VERIFICATION_ACCEPT,
            "@alice:example.org",
            {"transaction_id": "unknown"},
        )

        self.assertTrue(handled)
        handler._handle_accept.assert_not_awaited()
        self.assertEqual(handler._sessions, {})

    async def test_wrong_sender_or_device_cannot_drive_existing_flow(self):
        handler, dispatch_mod = self._make_handler()
        handler._sessions["txn"] = {
            "sender": "@alice:example.org",
            "their_device": "ALICE1",
            "state": "ready",
        }

        await handler.handle_verification_event(
            dispatch_mod.M_KEY_VERIFICATION_START,
            "@mallory:example.org",
            {"transaction_id": "txn", "from_device": "ALICE1"},
        )
        await handler.handle_verification_event(
            dispatch_mod.M_KEY_VERIFICATION_START,
            "@alice:example.org",
            {"transaction_id": "txn", "from_device": "ALICE2"},
        )

        handler._handle_start.assert_not_awaited()
        self.assertEqual(handler._sessions["txn"]["state"], "ready")

    async def test_terminal_session_cannot_be_revived(self):
        handler, dispatch_mod = self._make_handler()
        handler._sessions["txn"] = {
            "sender": "@alice:example.org",
            "their_device": "ALICE1",
            "state": "cancelled",
        }

        await handler.handle_verification_event(
            dispatch_mod.M_KEY_VERIFICATION_READY,
            "@alice:example.org",
            {"transaction_id": "txn", "from_device": "ALICE1"},
        )

        handler._handle_ready.assert_not_awaited()
        self.assertEqual(handler._sessions["txn"]["state"], "cancelled")


class MatrixV101HandlerDefenseTests(unittest.IsolatedAsyncioTestCase):
    def _make_start_handler(self):
        start_mod = load_module("e2ee.verification.flow_start.handshake.start")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            start_mod.SASVerificationFlowStartEventMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = Harness()
        handler._sessions = {}
        handler._mask_identifier = lambda value: str(value)
        handler._mask_txn_id = lambda value: str(value)
        handler.auto_verify_mode = "auto_accept"
        handler.user_id = "@alice:example.org"
        handler.device_id = "ALICE1"
        handler._send_accept = mock.AsyncMock()
        handler._send_in_room_accept = mock.AsyncMock()
        handler._send_cancel = mock.AsyncMock()
        handler._handle_reciprocate_start = mock.AsyncMock(return_value=False)
        handler._query_request_verification_keys = mock.AsyncMock()
        return handler

    async def test_direct_legacy_sas_start_creates_bound_session_and_accepts(self):
        handler = self._make_start_handler()

        await handler._handle_start(
            "@bob:example.org",
            {
                "transaction_id": "legacy",
                "from_device": "BOB1",
                "method": "m.sas.v1",
            },
            "legacy",
        )

        session = handler._sessions["legacy"]
        self.assertEqual(session["sender"], "@bob:example.org")
        self.assertEqual(session["from_device"], "BOB1")
        self.assertTrue(session["legacy_standalone_start"])
        self.assertEqual(session["state"], "started")
        handler._query_request_verification_keys.assert_awaited_once()
        handler._send_accept.assert_awaited_once()

    async def test_unknown_qr_reciprocate_cannot_create_legacy_flow(self):
        handler = self._make_start_handler()

        await handler._handle_start(
            "@bob:example.org",
            {
                "transaction_id": "unknown-qr",
                "from_device": "BOB1",
                "method": "m.reciprocate.v1",
                "secret": "not-bound-to-a-qr",
            },
            "unknown-qr",
        )

        self.assertNotIn("unknown-qr", handler._sessions)
        handler._send_accept.assert_not_awaited()
        handler._send_cancel.assert_awaited_once()
        self.assertEqual(handler._send_cancel.await_args.args[3], "m.unknown_transaction")

    async def test_simultaneous_same_method_uses_lexicographic_tiebreak(self):
        handler = self._make_start_handler()
        handler._sessions["txn"] = {
            "sender": "@bob:example.org",
            "their_device": "BOB1",
            "state": "ready",
            "we_are_initiator": True,
            "start_content": {"method": "m.sas.v1"},
        }

        await handler._handle_start(
            "@bob:example.org",
            {"from_device": "BOB1", "method": "m.sas.v1"},
            "txn",
        )

        # @bob is lexicographically larger than @alice, therefore Bob's start is ignored.
        self.assertEqual(handler._sessions["txn"]["state"], "ready")
        self.assertTrue(handler._sessions["txn"]["we_are_initiator"])
        handler._send_accept.assert_not_awaited()

    async def test_simultaneous_different_methods_cancel(self):
        handler = self._make_start_handler()
        handler._sessions["txn"] = {
            "sender": "@bob:example.org",
            "their_device": "BOB1",
            "state": "ready",
            "we_are_initiator": True,
            "start_content": {"method": "m.sas.v1"},
        }

        await handler._handle_start(
            "@bob:example.org",
            {"from_device": "BOB1", "method": "com.example.other"},
            "txn",
        )

        self.assertEqual(handler._sessions["txn"]["state"], "cancelled")
        self.assertEqual(
            handler._sessions["txn"]["cancel_code"], "m.unexpected_message"
        )
        handler._send_cancel.assert_awaited_once()


class MatrixV101InRoomSessionCreationTests(unittest.TestCase):
    def test_orphan_room_event_does_not_create_session(self):
        session_mod = load_module("e2ee.verification.event.room_dispatch.core.session")
        handler = session_mod.SASVerificationRoomEventDispatchSessionMixin()
        handler._sessions = {}
        handler._mask_txn_id = lambda value: str(value)

        ignored = handler._prepare_in_room_session(
            "txn",
            "!room:example.org",
            "m.key.verification.start",
            False,
        )

        self.assertTrue(ignored)
        self.assertEqual(handler._sessions, {})

    def test_room_request_creates_only_context_placeholder(self):
        session_mod = load_module("e2ee.verification.event.room_dispatch.core.session")
        handler = session_mod.SASVerificationRoomEventDispatchSessionMixin()
        handler._sessions = {}
        handler._mask_txn_id = lambda value: str(value)

        ignored = handler._prepare_in_room_session(
            "$request-event",
            "!room:example.org",
            "m.room.message",
            True,
        )

        self.assertFalse(ignored)
        self.assertTrue(handler._sessions["$request-event"]["_room_context_only"])
        self.assertEqual(
            handler._sessions["$request-event"]["room_id"], "!room:example.org"
        )
        self.assertTrue(handler._sessions["$request-event"]["is_in_room"])


if __name__ == "__main__":
    unittest.main()

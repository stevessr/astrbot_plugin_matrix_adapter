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


class MatrixV101PredecessorOrderingTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _identity_helpers(handler):
        handler._mask_identifier = lambda value: str(value)
        handler._mask_txn_id = lambda value: str(value)
        handler._send_cancel = mock.AsyncMock()
        return handler

    async def test_ready_out_of_order_cancels_transaction(self):
        ready_mod = load_module("e2ee.verification.flow_start.handshake.ready")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            ready_mod.SASVerificationFlowReadyMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = self._identity_helpers(Harness())
        handler._sessions = {
            "txn": {
                "sender": "@bob:example.org",
                "their_device": "BOB1",
                "state": "ready",
                "we_started_it": True,
            }
        }
        handler._maybe_prepare_self_verification_qr = mock.AsyncMock(return_value=False)
        handler._supports_method = lambda methods, method: method in methods
        handler._send_start = mock.AsyncMock()

        await handler._handle_ready(
            "@bob:example.org",
            {"from_device": "BOB1", "methods": ["m.sas.v1"]},
            "txn",
        )

        self.assertEqual(handler._sessions["txn"]["state"], "cancelled")
        self.assertEqual(
            handler._sessions["txn"]["cancel_code"], "m.unexpected_message"
        )
        handler._send_start.assert_not_awaited()

    async def test_accept_rejects_algorithm_not_offered_by_start(self):
        accept_mod = load_module("e2ee.verification.flow_start.handshake.accept")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            accept_mod.SASVerificationFlowAcceptMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = self._identity_helpers(Harness())
        handler.auto_verify_mode = "auto_accept"
        handler._send_key = mock.AsyncMock()
        handler._send_in_room_key = mock.AsyncMock()
        handler._sessions = {
            "txn": {
                "sender": "@bob:example.org",
                "their_device": "BOB1",
                "state": "start_sent",
                "we_are_initiator": True,
                "start_sent": True,
                "start_content": {
                    "method": "m.sas.v1",
                    "key_agreement_protocols": ["curve25519-hkdf-sha256"],
                    "hashes": ["sha256"],
                    "message_authentication_codes": ["hkdf-hmac-sha256.v2"],
                    "short_authentication_string": ["decimal", "emoji"],
                },
            }
        }

        await handler._handle_accept(
            "@bob:example.org",
            {
                "from_device": "BOB1",
                "method": "m.sas.v1",
                "commitment": "commitment",
                "key_agreement_protocol": "curve25519-hkdf-sha256",
                "hash": "com.example.not-offered",
                "message_authentication_code": "hkdf-hmac-sha256.v2",
                "short_authentication_string": ["decimal"],
            },
            "txn",
        )

        self.assertEqual(handler._sessions["txn"]["state"], "cancelled")
        self.assertEqual(handler._sessions["txn"]["cancel_code"], "m.unknown_method")
        handler._send_key.assert_not_awaited()

    async def test_key_before_accept_is_unexpected(self):
        key_mod = load_module("e2ee.verification.flow_key.key.core.core")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            key_mod.SASVerificationFlowKeyCoreOrchestratorMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = self._identity_helpers(Harness())
        handler._sessions = {
            "txn": {
                "sender": "@bob:example.org",
                "their_device": "BOB1",
                "state": "start_sent",
                "method": "m.sas.v1",
                "we_are_initiator": True,
                "start_sent": True,
                "key_sent": True,
            }
        }

        await handler._handle_key(
            "@bob:example.org",
            {"from_device": "BOB1", "key": "peer-key"},
            "txn",
        )

        self.assertEqual(handler._sessions["txn"]["state"], "cancelled")
        self.assertEqual(
            handler._sessions["txn"]["cancel_code"], "m.unexpected_message"
        )

    async def test_mac_before_key_exchange_is_unexpected(self):
        mac_mod = load_module("e2ee.verification.flow_key.mac.core.core.core")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            mac_mod.SASVerificationFlowMACOrchestratorMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = self._identity_helpers(Harness())
        handler._sessions = {
            "txn": {
                "sender": "@bob:example.org",
                "their_device": "BOB1",
                "state": "accepted",
                "method": "m.sas.v1",
                "key_sent": True,
            }
        }

        await handler._handle_mac(
            "@bob:example.org",
            {
                "from_device": "BOB1",
                "mac": {"ed25519:BOB1": "mac"},
                "keys": "keys-mac",
            },
            "txn",
        )

        self.assertEqual(handler._sessions["txn"]["state"], "cancelled")
        self.assertEqual(
            handler._sessions["txn"]["cancel_code"], "m.unexpected_message"
        )

    async def test_in_room_ready_continues_with_in_room_start(self):
        ready_mod = load_module("e2ee.verification.flow_start.handshake.ready")
        guard_mod = load_module("e2ee.verification.utils.session")

        class Harness(
            ready_mod.SASVerificationFlowReadyMixin,
            guard_mod.SASVerificationFlowSessionGuardMixin,
        ):
            pass

        handler = self._identity_helpers(Harness())
        handler.user_id = "@alice:example.org"
        handler._sessions = {
            "txn": {
                "sender": "@bob:example.org",
                "their_device": "BOB1",
                "state": "request_sent",
                "we_started_it": True,
                "is_in_room": True,
                "room_id": "!room:example.org",
            }
        }
        handler._maybe_prepare_self_verification_qr = mock.AsyncMock(return_value=False)
        handler._supports_method = lambda methods, method: method in methods
        handler._send_in_room_start = mock.AsyncMock()
        handler._send_start = mock.AsyncMock()

        await handler._handle_ready(
            "@bob:example.org",
            {"from_device": "BOB1", "methods": ["m.sas.v1"]},
            "txn",
        )

        handler._send_in_room_start.assert_awaited_once_with(
            "!room:example.org", "txn"
        )
        handler._send_start.assert_not_awaited()

    async def test_manual_done_waits_for_peer_mac_verification(self):
        done_mod = load_module("e2ee.verification.flow_key.mac.core.done")
        handler = done_mod.SASVerificationFlowMACDoneMixin()
        handler.auto_verify_mode = "manual"
        handler._send_done = mock.AsyncMock()
        handler._send_in_room_done = mock.AsyncMock()
        session = {
            "their_device": "BOB1",
            "manual_approved": True,
            "mac_sent": True,
            "mac_verified": False,
        }

        await handler._send_mac_done(
            session,
            "@bob:example.org",
            "txn",
            False,
            None,
        )
        handler._send_done.assert_not_awaited()

        session["mac_verified"] = True
        await handler._send_mac_done(
            session,
            "@bob:example.org",
            "txn",
            False,
            None,
        )
        handler._send_done.assert_awaited_once_with(
            "@bob:example.org", "BOB1", "txn"
        )
        self.assertTrue(session["done_sent"])


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

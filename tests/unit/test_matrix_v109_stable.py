import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV109PushRuleTests(unittest.IsolatedAsyncioTestCase):
    async def test_suppress_edits_rule_uses_stable_default_rule(self):
        mod = load_module("client.push_mixin.rules.query")
        calls = []

        class Client(mod.PushRuleQueryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"enabled": True}

        enabled = await Client().is_suppress_edits_push_rule_enabled()
        self.assertTrue(enabled)
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(
            calls[0][1],
            "/_matrix/client/v3/pushrules/global/override/m.rule.suppress_edits/enabled",
        )

    async def test_suppress_edits_rule_requires_explicit_true(self):
        mod = load_module("client.push_mixin.rules.query")

        class Client(mod.PushRuleQueryMixin):
            async def _request(self, method, endpoint, **kwargs):
                return {"enabled": False}

        self.assertFalse(await Client().is_suppress_edits_push_rule_enabled())


class MatrixV109SpaceViaTests(unittest.TestCase):
    def test_via_is_preserved_for_space_events(self):
        # v1.9 clarifies that m.space.child / m.space.parent require `via`.
        # The adapter's generic event model must therefore preserve the field.
        mod = load_module("client.event_types.base")
        event = mod.MatrixEvent.from_dict(
            {
                "event_id": "$space",
                "sender": "@alice:example.org",
                "origin_server_ts": 1,
                "type": "m.space.child",
                "state_key": "!child:example.org",
                "content": {"via": ["example.org", "elsewhere.org"]},
            },
            "!space:example.org",
        )
        self.assertEqual(event.content["via"], ["example.org", "elsewhere.org"])


if __name__ == "__main__":
    unittest.main()

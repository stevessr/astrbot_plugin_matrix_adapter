"""Authorization-code preparation and browser callback for the OAuth2 login flow."""

from urllib.parse import urlencode

from ...core import OAuth2CallbackServer, _log


async def _prepare_login_client(self) -> None:
    """Arm the webhook callback receiver and register a client if needed."""
    if not self.redirect_uri:
        raise RuntimeError(
            "Matrix OAuth2 requires AstrBot unified webhook redirect_uri"
        )
    self.callback_server = OAuth2CallbackServer(self.redirect_uri)
    self.redirect_uri = await self.callback_server.start()
    _log("info", f"OAuth2 callback URL: {self.redirect_uri}")

    if not self.client_id:
        _log(
            "info",
            "No client_id provided, attempting dynamic client registration...",
        )
        try:
            registration = await self._register_client(self.redirect_uri)
            self.client_id = registration["client_id"]
            self.client_secret = registration.get("client_secret")
            _log("info", f"✅ Registered as client: {self.client_id}")
        except Exception as e:
            _log("error", f"Dynamic registration failed: {e}")
            raise Exception(
                "No client_id provided and dynamic registration failed. "
                "Please provide a client_id in the configuration."
            )


async def _perform_authorization(self, auth_endpoint: str) -> tuple[str, str]:
    """Build the authorization URL, wait for the browser callback, return code."""
    state = self._generate_state()
    pkce_verifier = self._generate_pkce_verifier()
    pkce_challenge = self._generate_pkce_challenge(pkce_verifier)
    if self.callback_server:
        self.callback_server.prepare_callback(expected_state=state)

    # Build authorization URL
    auth_params = {
        "response_type": "code",
        "client_id": self.client_id,
        "redirect_uri": self.redirect_uri,
        "scope": " ".join(self.scopes),
        "state": state,
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{auth_endpoint}?{urlencode(auth_params)}"

    _log("info", "=" * 60)
    _log("info", "OAuth2 Authentication Required")
    _log("info", "=" * 60)
    _log("info", f"Please open this URL in your browser:\n\n {auth_url} \n")
    _log("info", "Waiting for authentication...")
    _log("info", "=" * 60)

    return await self.callback_server.wait_for_callback(), pkce_verifier

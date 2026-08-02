"""Matrix email and phone validation token operations."""

from typing import Any


class AccountTokenMixin:
    async def request_email_token(
        self,
        email: str,
        client_secret: str,
        send_attempt: int,
        next_link: str | None = None,
    ) -> dict[str, Any]:
        """
        Request a token for email validation

        Args:
            email: Email address
            client_secret: Client secret
            send_attempt: Send attempt counter
            next_link: Optional link after validation

        Returns:
            Token response
        """
        data: dict[str, Any] = {
            "email": email,
            "client_secret": client_secret,
            "send_attempt": send_attempt,
        }
        if next_link:
            data["next_link"] = next_link
        return await self._request(
            "POST", "/_matrix/client/v3/account/3pid/email/requestToken", data=data
        )

    async def request_msisdn_token(
        self,
        country: str,
        phone_number: str,
        client_secret: str,
        send_attempt: int,
        next_link: str | None = None,
    ) -> dict[str, Any]:
        """
        Request a token for phone number validation

        Args:
            country: Country code (ISO 3166-1 alpha-2)
            phone_number: Phone number
            client_secret: Client secret
            send_attempt: Send attempt counter
            next_link: Optional link after validation

        Returns:
            Token response
        """
        data: dict[str, Any] = {
            "country": country,
            "phone_number": phone_number,
            "client_secret": client_secret,
            "send_attempt": send_attempt,
        }
        if next_link:
            data["next_link"] = next_link
        return await self._request(
            "POST", "/_matrix/client/v3/account/3pid/msisdn/requestToken", data=data
        )

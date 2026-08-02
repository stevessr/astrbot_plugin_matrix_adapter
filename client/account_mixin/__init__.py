"""Composable Matrix account and third-party identifier operations."""

from typing import Any

from .account import AccountOperationsMixin
from .threepid import AccountThreepidMixin
from .tokens import AccountTokenMixin


class AccountMixin(AccountOperationsMixin, AccountThreepidMixin, AccountTokenMixin):
    """Account management methods for Matrix client"""

    pass


# Preserve direct method attributes exposed by the former mixin.
AccountMixin.change_password = AccountOperationsMixin.__dict__["change_password"]
AccountMixin.deactivate_account = AccountOperationsMixin.__dict__["deactivate_account"]
AccountMixin.get_3pid = AccountThreepidMixin.__dict__["get_3pid"]
AccountMixin.add_3pid = AccountThreepidMixin.__dict__["add_3pid"]
AccountMixin.delete_3pid = AccountThreepidMixin.__dict__["delete_3pid"]
AccountMixin.bind_3pid = AccountThreepidMixin.__dict__["bind_3pid"]
AccountMixin.unbind_3pid = AccountThreepidMixin.__dict__["unbind_3pid"]
AccountMixin.request_email_token = AccountTokenMixin.__dict__["request_email_token"]
AccountMixin.request_msisdn_token = AccountTokenMixin.__dict__["request_msisdn_token"]


__all__ = ["AccountMixin", "Any"]

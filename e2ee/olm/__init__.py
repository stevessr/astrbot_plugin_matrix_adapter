"""Olm and Megolm machine implementation."""

from .types import (
    VODOZEMAC_AVAILABLE,
    Account,
    AnyOlmMessage,
    Curve25519PublicKey,
    Ed25519PublicKey,
    Ed25519Signature,
    GroupSession,
    InboundGroupSession,
    PreKeyMessage,
    Session,
)

__all__ = [
    "OlmMachine",
    "OlmMachineAccountMixin",
    "OlmMachineKeysMixin",
    "OlmMachineOlmMixin",
    "VODOZEMAC_AVAILABLE",
    "Account",
    "AnyOlmMessage",
    "Curve25519PublicKey",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "GroupSession",
    "InboundGroupSession",
    "PreKeyMessage",
    "Session",
]


def __getattr__(name: str):
    if name == "OlmMachine":
        from .core import OlmMachine

        return OlmMachine
    if name == "OlmMachineAccountMixin":
        from .account import OlmMachineAccountMixin

        return OlmMachineAccountMixin
    if name == "OlmMachineKeysMixin":
        from .keys import OlmMachineKeysMixin

        return OlmMachineKeysMixin
    if name == "OlmMachineOlmMixin":
        from .olm import OlmMachineOlmMixin

        return OlmMachineOlmMixin
    raise AttributeError(name)

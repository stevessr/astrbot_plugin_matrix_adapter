"""Sticker service construction for adapter service composition."""

from __future__ import annotations

from pathlib import Path

from ....sticker import StickerAvailabilityStore, StickerPackSyncer, StickerStorage


def _init_sticker_services(
    user_storage_dir: Path, client
) -> tuple[StickerAvailabilityStore, StickerStorage, StickerPackSyncer]:
    """Build the sticker availability store, storage, and syncer."""
    available_path = Path(user_storage_dir) / "sticker_available.json"
    sticker_available = StickerAvailabilityStore(available_path)
    sticker_storage = StickerStorage(availability_store=sticker_available)
    sticker_syncer = StickerPackSyncer(
        storage=sticker_storage,
        client=client,
        availability_store=sticker_available,
    )
    return sticker_available, sticker_storage, sticker_syncer

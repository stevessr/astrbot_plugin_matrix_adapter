# Changelog

## Unreleased
- Added `matrix_force_message_type=stalk` to archive incoming messages to per-room JSONL files under `store_path/stalk_archive/`.
- In `stalk` mode, messages are recorded but not dispatched to AstrBot handlers.
- Extended message type forcing to support `stalk` alongside `auto`/`private`/`group`.
- Added Matrix poll sending via `MatrixSender.send_poll` and `Poll` message component.
- Switched media config/download/thumbnail/preview to authenticated media endpoints (`/_matrix/client/v1/media/*`) per the latest spec, removing deprecated `/_matrix/media/*` fallbacks.
- Replaced room `initial_sync` with `/sync` + room filter to match the latest spec.
- Added automatic SSO fallback when OAuth2 auto-discovery is unavailable but `m.login.sso` is supported.
- Sticker index/cache are global; per-account availability stored separately. Sticker cache is now organized by room/pack name.
- Sticker list/search now auto-filters to the account's available sticker IDs.
- Added v1.17-compliant media message handling: encrypted file decryption for media/stickers, media captions parsing, and filename fields for image/audio/video sends.
- Added full room state handling for m.room.* state events (name/topic/avatar/join_rules/power_levels/history_visibility and more), persisted per-room.

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

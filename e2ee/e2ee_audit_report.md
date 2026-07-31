# E2EE Module Audit Report

## Summary

Audited 30 Python files in `/e2ee/` (~7000 lines). The module is well-structured with sensible
architecture: `E2EEManager` via cooperative mixins, `CryptoStore` for persistence, `OlmMachine`
wrapping vodozemac, `CrossSigning`, `KeyBackup`, and `SASVerification`. Error handling is
generally good with structured fallback paths. However, several medium-severity issues exist
around thread-safety assumptions, data-corruption paths in key backup restore, and race
conditions in the initialization/shutdown lifecycle.

---

## HIGH SEVERITY

### H1. Key backup restore corrupts data on pickle fallback (key_backup_backup.py:588-591)

**File:** `key_backup_backup.py:588-591`
**Severity:** HIGH
**Category:** Data corruption / Logic bug

```python
except json.JSONDecodeError:
    # 可能是 pickle 格式
    self.store.save_megolm_inbound(session_id, plaintext)
    restored += 1
```

When `json.loads(plaintext)` fails, the code assumes `plaintext` is a vodozemac pickle and
stores it directly via `save_megolm_inbound(session_id, plaintext)`. However, `plaintext` at
this point is the **decrypted backup data** (a `str` or `bytes` decoded from the backup's
AES/Curve25519 layer) — NOT a vodozemac pickle. The backup format never produces raw
vodozemac pickles; it always stores JSON-serialized `BackedUpSessionData`.

**Impact:** Every Megolm session imported through this fallback path stores garbage. The
stored value will fail to deserialize on the next `InboundGroupSession.from_pickle()` call,
causing permanent loss of that session key. The session is counted as `restored` but is
actually corrupted.

**Fix:** Remove the pickle fallback entirely. A `JSONDecodeError` from backup data indicates
either data corruption or an incompatible backup format; increment `skipped` and log a
warning instead.

---

### H2. Race on `_megolm_replay` dictionary from concurrent coroutines (crypto_store.py:545-558)

**File:** `crypto_store.py:545-558`
**Severity:** HIGH
**Category:** Race condition

```python
indexes = self._megolm_replay.setdefault(session_id, {})
index_key = str(message_index)
previous = indexes.get(index_key)
if previous is not None:
    return previous == event_identifier
indexes[index_key] = event_identifier
```

`_megolm_replay` is a plain `dict` mutated directly by the calling thread (the asyncio event
loop). Two coroutines that decrypt messages from the same Megolm session concurrently can
race on the `setdefault` and `indexes[index_key]` assignment:
1. Coroutine A checks `indexes.get(index_key)` -> `None`
2. Coroutine B checks `indexes.get(index_key)` -> `None`
3. Both write `indexes[index_key] = ...`
4. The second write wins; the first write is silently lost.
5. The lost write's `_save_record` fires asynchronously, so the persisted state may reflect
   either write nondeterministically.

While CPython's GIL makes individual `dict` operations atomic, the **check-then-set** pattern
is not atomic across coroutines. A replay attack using the same message index twice would
be allowed through if both decryption attempts arrive between the same `get`/`set` gap.

**Impact:** Theoretically allows replay of a Megolm message at the same index if two
decryption attempts race. Practically difficult to exploit, but violates the protocol's
replay-protection guarantee.

**Fix:** Use an `asyncio.Lock` per session, or perform the check-and-set atomically via a
dedicated method guarded by a lock keyed on `session_id`.

---

### H3. `_initialized` flag creates TOCTOU window with `close()` (e2ee_manager.py:222-245)

**File:** `e2ee_manager.py:222-245` across all mixins that check `self._initialized`
**Severity:** HIGH
**Category:** Race condition / Use-after-free

`close()` transitions:
```
self._initialized = False    # line 222
self.stop_key_share_check_task()
await key_share_task          # await point
self._store = None            # line 230
self._olm = None              # line 231
```

A coroutine that reads `self._initialized` as `True` between line 222 and line 230 will
continue execution with `self._olm` or `self._store` still alive. But after `close()` hits
line 230, that same coroutine may access `self._olm` and crash with `AttributeError` on
`None`.

The pattern is spread across ~15 guard points:
- `decrypt_event`, `encrypt_message`, `ensure_room_keys_sent`, `handle_room_key`,
  `_proactive_check_key_sharing`, `respond_to_key_request`, etc.

**Impact:** Non-deterministic `AttributeError: 'NoneType' object has no attribute '...'`
crashes during adapter shutdown when decrypt/encrypt tasks are in flight.

**Fix:** Replace the bare `bool` flag with a `try`/`except` pattern or hold a reference
count / shutdown event that blocks `close()` until in-flight operations complete. At
minimum, guard every `self._olm`/`self._store` access after the `_initialized` check
with a local reference + None check.

---

## MEDIUM SEVERITY

### M1. Olm session cache drops earliest sessions first (olm_machine_olm.py:49-50)

**File:** `olm_machine_olm.py:49-50`
**Severity:** MEDIUM
**Category:** Resource management

```python
sessions.append(session)
if len(sessions) > MAX_OLM_SESSIONS_PER_PEER:
    sessions.pop(0)
```

The per-peer Olm session limit (5) evicts from the front (oldest). If a burst of PreKey
messages from the same peer creates many sessions rapidly, the first/earliest session is
dropped. The comment correctly identifies that "older sessions are retained for decryption
of out-of-order messages," but with only 5 slots and `pop(0)` eviction, a burst of 6+
PreKey messages can evict sessions that are still needed for delayed messages.

**Impact:** Intermittent decryption failures for out-of-order Olm messages in high-traffic
scenarios.

**Fix:** Increase the limit or use an LRU eviction strategy (`collections.OrderedDict`
or check last-used timestamp).

---

### M2. `_discard_outbound_session` leaks in-flight locks (e2ee_manager_sessions.py:66-73)

**File:** `e2ee_manager_sessions.py:66-73`
**Severity:** MEDIUM
**Category:** Resource leak

```python
lock = locks.get(session_id) if isinstance(locks, dict) else None
if lock is not None and not lock.locked():
    locks.pop(session_id, None)
```

When a Megolm session is rotated while another task holds the per-session
`_room_key_share_locks[session_id]` lock, the lock entry is leaked because `lock.locked()`
returns `True`. Over time, many stale `asyncio.Lock` objects accumulate in the dict.

**Impact:** Gradual memory growth in long-running adapters with frequent session rotation.

**Fix:** Always remove the lock entry from the dict. The lock itself is garbage-collected
when the dict entry is gone and the last reference is released.

---

### M3. `_request_room_key` targets only own user (e2ee_manager_requests.py:163)

**File:** `e2ee_manager_requests.py:163`
**Severity:** MEDIUM
**Category:** Logic / Spec compliance

```python
recipients = {self.user_id}
```

Room-key requests (`m.room_key_request`) are sent only to our own user. According to the
Matrix spec, these should also be sent to the original sender of the encrypted event when
that sender is a different user, so the sender's devices can reply with the key. This is
a deliberate restriction (confirmed by the code comment on line 161-162:
"Matrix key requests are restricted to verified devices of our own user").

**Impact:** If another user's device sent the encrypted message and our device is missing
the Megolm session, we never request the key from that user's devices. Recovery is only
possible via key backup or forwarding.

**Fix:** Add the original `sender_key`'s user as a secondary recipient when it differs
from `self.user_id`.

---

### M4. `respond_to_key_request` bypasses `_olm_recovery_attempts` rate-limit (e2ee_manager_requests.py:686-695)

**File:** `e2ee_manager_requests.py:686-695`
**Severity:** MEDIUM
**Category:** Rate-limit bypass

When `_encrypt_to_device` fails (no existing Olm session, no one-time key available),
`respond_to_key_request` falls back to sending `m.no_olm` via `_send_no_olm_withheld`.
But it does so without checking the `_olm_recovery_attempts` rate limit that governs
`_request_new_session`. This means the fallback `m.no_olm` can be emitted more frequently
than the spec's recommended one-per-hour rate.

**Impact:** Potential rate-limiting or DDoS flag from the homeserver.

**Fix:** Gate the `_send_no_olm_withheld` call behind the same rate-limit check used in
`_request_new_session`.

---

### M5. `_verify_recovery_key` tries both base64 variants due to spec ambiguity (key_backup_backup.py:249-256)

**File:** `key_backup_backup.py:249-256`
**Severity:** MEDIUM (design concern)
**Category:** Spec compliance / Interoperability

```python
public_key_std = base64.b64encode(pub_bytes).decode().rstrip("=")
if public_key_std != expected_public_key and public_key != expected_public_key:
```

The code generates the public key using both `base64.b64encode` (standard) and
`base64.urlsafe_b64encode`, trying to match the server's `public_key`. The comment
expresses uncertainty about which variant the server uses. This works in practice because
both are tried, but indicates the key derivation may not match the Matrix spec exactly.

**Impact:** No current bug (both variants are tried), but fragile. The `urlsafe` variant is
not standard Matrix usage and a future homeserver using only standard base64 would match
the first check, masking the uncertainty.

---

### M6. `handle_secret_request` trusts `requesting_device_id` from content over event metadata (e2ee_manager_secrets.py:61)

**File:** `e2ee_manager_secrets.py:61`
**Severity:** MEDIUM
**Category:** Security / Input validation

```python
requesting_device_id = content.get("requesting_device_id", sender_device)
```

The device ID is taken from the event `content` rather than exclusively using the
authenticated `sender_device` from the to-device message metadata. While `sender_device`
is used as fallback, a crafted event with a mismatched `requesting_device_id` in the
content would be processed. The subsequent device validation checks mitigate this, but
relying on unauthenticated content fields is a defense-in-depth violation.

**Impact:** Low practical risk (device verification check still applies), but violates the
principle of trusting metadata over content.

---

## LOW SEVERITY

### L1. `CryptoStore._submit_persist_job` writes data without defensive copy (crypto_store.py:161-196)

**File:** `crypto_store.py:230-241` (via `_save_record`)
`_save_record` calls `_clone_record_data(data)` before submitting the job, which does
`copy.deepcopy(data)`. If deepcopy fails, it returns the original data (line 129-133),
and the original could be mutated after the async job captures it. Low severity because
deepcopy rarely fails on standard dicts/lists.

---

### L2. `verify_user` mutates server response dict (cross_signing.py:1225-1233)

**File:** `cross_signing.py:1225-1233`

```python
master_key["signatures"] = existing_signatures
```

`verify_user` modifies the `master_key` dict directly (received from the server response)
rather than a copy. If the caller reuses the response, the embedded signatures are wrong.
Currently no caller reuses, but the mutation is a latent bug.

---

### L3. `verify_user` does not use `_upload_signature_and_confirm` pattern (cross_signing.py:1244-1246)

**File:** `cross_signing.py:1244-1246`

`sign_device` and `sign_master_key_with_device` both use `_upload_signature_and_confirm`
which polls the server for up to 5 seconds to verify the signature was accepted. `verify_user`
skips this verification - it uploads the signature and trusts the response without
confirming it appears in the server state.

---

### L4. `_megolm_message_index` field popped from decrypted plaintext (e2ee_manager_decrypt.py:213-214)

**File:** `e2ee_manager_decrypt.py:213-214`

```python
message_index = plaintext.pop(MEGOLM_MESSAGE_INDEX_FIELD, None)
```

The custom `_astrbot_megolm_message_index` field is removed from the decrypted content as
a side effect. Callers receiving the returned dict will not see this field. By design, but
surprising.

---

### L5. `DeviceStore.is_trusted` uses exact string comparison (device_store.py:57-59)

**File:** `device_store.py:57-59`

The fingerprint comparison is strict string equality. If one side has unpadded base64 and
the other has padded, they won't match even though the keys are identical. Currently both
sides are consistent (unpadded), but cross-version format changes could silently break trust.

---

### L6. `shared_history = shared_history is True` (e2ee_manager_sessions.py:751)

**File:** `e2ee_manager_sessions.py:751, olm_machine_megolm.py:376`

The type narrowing `shared_history is True` converts `None` (meaning "unknown/legacy") to
`False`. This is correct for the shareability gate but masks the distinction between
"known-non-shareable" and "unknown" in log messages.

---

### L7. `_olm_recovery_attempts` dict key scope mismatch (e2ee_manager_requests.py:64)

**File:** `e2ee_manager_requests.py:64`

```python
attempt_key = (target_user, target_device)
```

The recovery rate limit is keyed on `(user, device)`, but the `_olm_session` cache is keyed
on `sender_key` (Curve25519 key). If a device rotates its identity key, the rate-limit
counter for the old identity is orphaned and a new entry is created. This is unlikely with
vodozemac's stable keys but is a conceptual inconsistency.

---

### L8. `upload_room_keys` accesses private `_megolm_inbound` (key_backup_backup.py:383)

**File:** `key_backup_backup.py:383`

```python
session_ids = list(self.store._megolm_inbound)
```

Directly reads `store._megolm_inbound` (a private attribute). Should use a public accessor.
Breaks encapsulation.

---

## RACE CONDITION SUMMARY

| Location | Type | Severity |
|---|---|---|
| `crypto_store.py:545-558` | Check-then-set on shared dict | **HIGH** |
| `e2ee_manager.py:222-245` | TOCTOU with initialization flag | **HIGH** |
| `e2ee_manager_sessions.py:66-73` | Stale lock accumulation | MEDIUM |
| `e2ee_manager_sessions.py:448-531` | `_room_encryption_config` race (GIL-only) | LOW |
| `crypto_store.py:161-196` | Persist queue vs sync fallback | LOW |

## KEY LIFECYCLE CORRECTNESS

- **Device key upload:** `_upload_device_keys` runs before cross-signing and backup
  initialization. Sequential in `initialize()`. Correct.
- **OTK replenishment:** `ensure_sufficient_one_time_keys` is called from both
  `_upload_device_keys` (during init) and the runtime path. The `_last_otk_maintenance_ts`
  guard prevents too-frequent replenishment. Correct.
- **Megolm session rotation:** `encrypt_message` checks rotation period/msg-count and
  also shared-history consistency. Falls through to `_create_and_share_session` on
  rotation. Correct.
- **Room key sharing:** Per-session `asyncio.Lock` prevents duplicate distributions.
  `_room_key_share_cache` tracks which devices have received each session. Correct.
- **Forwarded key provenance:** `handle_room_key` validates the full forwarding chain,
  sender claimed keys, and device trust. Correct.
- **Cross-signing recovery:** Five-tier fallback (local keys -> SSSS -> device
  secrets -> force regen -> give up) covers all realistic recovery paths. Correct.

## ERROR HANDLING QUALITY

All database/storage operations have try/except wrappers with descriptive log messages.
The code consistently uses `getattr` with defaults to handle optional storage APIs across
backends. No bare `except:` found. The defensive pattern:

```python
method = getattr(self._store, "method_name", None)
if callable(method):
    method(...)
```

is used extensively and correctly for cross-mixin API compatibility.

One minor concern: several log messages include key material truncated with `[:8]`. This
is standard logging practice and acceptable for session IDs, but verify no unrecoverable
key material is logged during debugging sessions.

## VERDICT

The module is production-capable with the three HIGH-severity issues addressed:

1. **H1**: Remove the pickle fallback in key backup restore (data corruption on every
   legacy-format backup restore) -- MUST fix.
2. **H2**: Add per-session lock to `check_and_record_megolm_message_index` (replay
   protection bypass under concurrent decrypt) -- MUST fix.
3. **H3**: Protect all `_olm`/`_store` references against `None` during shutdown
   (`AttributeError` crashes on shutdown) -- MUST fix.

The MEDIUM issues (Olm session eviction, stale locks, room-key request targeting,
cross-signing verification gaps) should be addressed before a production deployment
but are not blocking.

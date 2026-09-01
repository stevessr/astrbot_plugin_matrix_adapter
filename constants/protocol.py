"""Matrix protocol and MSC extension constants."""

# 协议算法与格式
# 根据 Matrix 规范定义的标准加密算法标识符
# 参考：https://spec.matrix.org/latest/client-server-api/#end-to-end-encryption
OLM_ALGO = "m.olm.v1.curve25519-aes-sha2"
MEGOLM_ALGO = "m.megolm.v1.aes-sha2"
MEGOLM_BACKUP_ALGO = "m.megolm_backup.v1.curve25519-aes-sha2"
MEGOLM_BACKUP_INFO = "m.megolm_backup.v1"
MATRIX_HTML_FORMAT = "org.matrix.custom.html"

# 关系与线程常量
REL_TYPE_THREAD = "m.thread"
REL_TYPE_REPLACE = "m.replace"

# Extended relation type constants
REL_TYPE_REFERENCE = "m.reference"
REL_TYPE_ANNOTATION = "m.annotation"

# MSC4357 Live Messages
MSC4357_LIVE_MESSAGE_MARKER = "org.matrix.msc4357.live"
M_ROOM_LIVE_MESSAGING = "m.room.live_messaging"
MSC4357_LIVE_MESSAGING_STATE = "org.matrix.msc4357.live_messaging"

# Matrix v1.19 stable event types
M_KEY_BACKUP = "m.key_backup"
M_ROOM_IMAGE_PACK = "m.room.image_pack"
M_IMAGE_PACK_ROOMS = "m.image_pack.rooms"

# MSC1767 Extensible Events
MSC1767_TEXT_KEY = "org.matrix.msc1767.text"
MSC1767_HTML_KEY = "org.matrix.msc1767.html"
MSC1767_FILE_KEY = "org.matrix.msc1767.file"
MSC1767_IMAGE_KEY = "org.matrix.msc1767.image"
MSC1767_VIDEO_KEY = "org.matrix.msc1767.video"
MSC1767_AUDIO_KEY = "org.matrix.msc1767.audio"
MSC1767_CAPTION_KEY = "org.matrix.msc1767.caption"

# MSC3267 Extensible Media (m.media block inside message content)
M_MEDIA_KEY = "m.media"

# MSC3245 Voice Messages
MSC3245_VOICE_KEY = "org.matrix.msc3245.voice"
MSC3245_VOICE_V2_KEY = "org.matrix.msc3245.voice.v2"

# MSC3488 Location / MSC3489 Live Location Sharing
MSC3488_LOCATION_KEY = "org.matrix.msc3488.location"
MSC3488_ASSET_KEY = "org.matrix.msc3488.asset"
MSC3488_TS_KEY = "org.matrix.msc3488.ts"
MSC3489_BEACON_INFO_PREFIX = "org.matrix.msc3672.beacon_info"
MSC3489_BEACON_KEY = "org.matrix.msc3672.beacon"
M_BEACON_INFO = "m.beacon_info"
M_BEACON = "m.beacon"

# MSC2867 Marking Rooms as Unread
MSC2867_MARKED_UNREAD = "com.famedly.marked_unread"
M_MARKED_UNREAD = "m.marked_unread"

# MSC4140 Delayed Events (cancellable future events)
MSC4140_DELAY_QUERY = "org.matrix.msc4140.delay"
MSC4140_PARENT_DELAY_ID = "org.matrix.msc4140.parent_delay_id"
MSC4140_DELAYED_EVENTS_PATH = (
    "/_matrix/client/unstable/org.matrix.msc4140/delayed_events"
)

# MSC4144 Per-Message Profiles
MSC4144_PROFILE_KEY = "com.beeper.per_message_profile"
M_PROFILE_KEY = "m.per_message_profile"

# MSC3952 Intentional Mentions
M_MENTIONS_KEY = "m.mentions"

# MSC4133 Custom Profile Fields (extended profile)
MSC4133_PROFILE_PATH = "/_matrix/client/unstable/uk.tcpip.msc4133/profile"
M_PROFILE_FIELDS_CAPABILITY = "m.profile_fields"

# MSC4175 stable profile time zone (Matrix v1.16)
M_PROFILE_TIME_ZONE = "m.tz"
MSC4175_TIME_ZONE = "us.cloke.msc4175.tz"

# MSC4446 Allow moving the fully read marker to older events
# 用于 read_markers / receipt/m.fully_read 请求体，允许 m.fully_read 回移到更早事件
MSC4446_ALLOW_BACKWARD = "com.beeper.allow_backward"
MSC4446_CAPABILITY = "com.beeper.msc4446"

# MSC4310 MatrixRTC decline event (通话拒接)
M_RTC_DECLINE = "m.rtc.decline"
MSC4310_RTC_DECLINE = "org.matrix.msc4310.rtc.decline"

# MSC4319 Room member events for invite and knock rooms in the /sync response
# InvitedRoom/KnockedRoom 上携带完整 member 事件的 state 键（unstable）
MSC4319_STATE_KEY = "org.matrix.msc4319.state"

# MSC3381 Polls
M_POLL_START = "m.poll.start"
M_POLL_RESPONSE = "m.poll.response"
M_POLL_END = "m.poll.end"
MSC3381_POLL_START = "org.matrix.msc3381.poll.start"
MSC3381_POLL_RESPONSE = "org.matrix.msc3381.poll.response"
MSC3381_POLL_END = "org.matrix.msc3381.poll.end"
M_POLL_KIND_DISCLOSED = "m.disclosed"
M_POLL_KIND_UNDISCLOSED = "m.undisclosed"
M_POLL = "m.poll"

# MSC4495 Selective Presence (选择性在线状态)
M_PRESENCE_SHARING = "m.presence.sharing"
MSC4495_PRESENCE_SHARING = "org.continuwuity.presence_v2.msc4495.presence.sharing"
M_PRESENCE_PROMPTED = "m.presence.prompted"
MSC4495_PRESENCE_PROMPTED = "org.continuwuity.presence_v2.msc4495.presence.prompted"
M_ROOM_PRESENCE_SHARING = "m.room.presence_sharing"
MSC4495_ROOM_PRESENCE_SHARING = (
    "org.continuwuity.presence_v2.msc4495.room.presence_sharing"
)
# 服务器能力：capabilities.m.selective_presence 或 versions.unstable_features 列出 MSC4495_CAPABILITY
M_SELECTIVE_PRESENCE_CAP = "m.selective_presence"
MSC4495_SELECTIVE_PRESENCE_CAP = (
    "org.continuwuity.presence_v2.msc4495.selective_presence"
)
MSC4495_CAPABILITY = "org.continuwuity.presence_v2.msc4495"
# presence sharing 取值
PRESENCE_SHARING_ALLOW = "allow"
PRESENCE_SHARING_DENY = "deny"
PRESENCE_HINT_SUGGEST = "suggest"
PRESENCE_HINT_FORBID = "forbid"

__all__ = [name for name in globals() if not name.startswith("_")]

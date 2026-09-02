"""Matrix event, room-state, message, and authentication constants."""

# 通用事件类型
M_ROOM_MESSAGE = "m.room.message"
M_ROOM_REDACTION = "m.room.redaction"
M_STICKER = "m.sticker"
M_REACTION = "m.reaction"
M_LOCATION = "m.location"
M_ROOM_ENCRYPTED = "m.room.encrypted"
M_ROOM_KEY = "m.room_key"
M_ROOM_KEY_REQUEST = "m.room_key_request"
M_ROOM_KEY_WITHHELD = "m.room_key.withheld"
M_FORWARDED_ROOM_KEY = "m.forwarded_room_key"
M_ROOM_MEMBER = "m.room.member"
MEMBERSHIP_JOIN = "join"
MEMBERSHIP_INVITE = "invite"
MEMBERSHIP_LEAVE = "leave"
MEMBERSHIP_BAN = "ban"
MEMBERSHIP_KNOCK = "knock"

# 内容键名（事件负载中使用的固定 JSON 字段名）
CONTENT_KEY_RELATES_TO = "m.relates_to"
CONTENT_KEY_NEW_CONTENT = "m.new_content"
CONTENT_KEY_IN_REPLY_TO = "m.in_reply_to"
CONTENT_KEY_FULLY_READ = "m.fully_read"
CONTENT_KEY_READ_RECEIPT = "m.read"

# 房间状态事件类型
# 参考：https://spec.matrix.org/latest/client-server-api/#room-events
M_ROOM_NAME = "m.room.name"
M_ROOM_TOPIC = "m.room.topic"
M_ROOM_AVATAR = "m.room.avatar"
M_ROOM_CREATE = "m.room.create"
M_ROOM_ENCRYPTION = "m.room.encryption"
M_ROOM_SERVER_ACL = "m.room.server_acl"
M_ROOM_TOMBSTONE = "m.room.tombstone"
M_ROOM_POWER_LEVELS = "m.room.power_levels"
M_ROOM_JOIN_RULES = "m.room.join_rules"
M_ROOM_HISTORY_VISIBILITY = "m.room.history_visibility"
M_ROOM_GUEST_ACCESS = "m.room.guest_access"
M_ROOM_CANONICAL_ALIAS = "m.room.canonical_alias"
M_ROOM_ALIASES = "m.room.aliases"
M_ROOM_PINNED_EVENTS = "m.room.pinned_events"
M_ROOM_THIRD_PARTY_INVITE = "m.room.third_party_invite"
M_SPACE_CHILD = "m.space.child"
M_SPACE_PARENT = "m.space.parent"

# 消息类型（msgtype）
MSGTYPE_TEXT = "m.text"
MSGTYPE_NOTICE = "m.notice"
MSGTYPE_EMOTE = "m.emote"
MSGTYPE_IMAGE = "m.image"
MSGTYPE_FILE = "m.file"
MSGTYPE_VIDEO = "m.video"
MSGTYPE_AUDIO = "m.audio"
MSGTYPE_STICKER = "m.sticker"
MSGTYPE_LOCATION = "m.location"
MSGTYPE_REDACTION = "m.redaction"
MSGTYPE_REACTION = "m.reaction"

# 用户认证类型
LOGIN_TYPE_PASSWORD = "m.login.password"
LOGIN_TYPE_TOKEN = "m.login.token"
LOGIN_TYPE_SSO = "m.login.sso"
LOGIN_TYPE_DUMMY = "m.login.dummy"
LOGIN_TYPE_OAUTH = "m.oauth"

# 特定 API 参数键名
MSC4140_DELAY_KEY = "org.matrix.msc4140.delay"
MSC4140_PARENT_DELAY_ID_KEY = "org.matrix.msc4140.parent_delay_id"
ID_TYPE_USER = "m.id.user"

__all__ = [name for name in globals() if not name.startswith("_")]

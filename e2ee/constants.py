"""E2EE-local constants.

Protocol-wide event names and algorithms remain in :mod:`..constants`.  This
module owns policy values and state local to the E2EE implementation so that
the manager, verification, and cross-signing modules do not grow their own
copies of protocol strings or timing values.
"""

from ..constants import (
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
    SECRET_MEGOLM_BACKUP_V1,
)

# Olm / key-maintenance policy
DEFAULT_PROACTIVE_KEY_SHARE_INTERVAL_SEC = 30
DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC = 30.0
DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC = 5.0
DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC = 300.0
# Matrix recommends creating at most one replacement Olm session per peer/hour.
DEFAULT_OLM_RECOVERY_RETRY_SEC = 3600.0
DEFAULT_MEGOLM_ROTATION_PERIOD_MS = 7 * 24 * 60 * 60 * 1000
DEFAULT_MEGOLM_ROTATION_PERIOD_MSGS = 100
M_DUMMY = "m.dummy"
MEGOLM_MESSAGE_INDEX_FIELD = "_astrbot_megolm_message_index"

# Matrix room history visibility.  Missing or invalid state is ``shared``.
HISTORY_VISIBILITY_INVITED = "invited"
HISTORY_VISIBILITY_JOINED = "joined"
HISTORY_VISIBILITY_SHARED = "shared"
HISTORY_VISIBILITY_WORLD_READABLE = "world_readable"
DEFAULT_HISTORY_VISIBILITY = HISTORY_VISIBILITY_SHARED
VALID_HISTORY_VISIBILITIES = frozenset(
    {
        HISTORY_VISIBILITY_INVITED,
        HISTORY_VISIBILITY_JOINED,
        HISTORY_VISIBILITY_SHARED,
        HISTORY_VISIBILITY_WORLD_READABLE,
    }
)
SHAREABLE_HISTORY_VISIBILITIES = frozenset(
    {HISTORY_VISIBILITY_SHARED, HISTORY_VISIBILITY_WORLD_READABLE}
)
INVITE_KEY_SHARE_VISIBILITIES = frozenset(
    {
        HISTORY_VISIBILITY_INVITED,
        HISTORY_VISIBILITY_SHARED,
        HISTORY_VISIBILITY_WORLD_READABLE,
    }
)

# m.room_key.withheld codes.  ``m.history_not_shared`` is valid inside a
# Matrix v1.19 RoomKeyBundle, but SHOULD NOT be emitted as a to-device
# m.room_key.withheld event.
WITHHELD_BLACKLISTED = "m.blacklisted"
WITHHELD_UNVERIFIED = "m.unverified"
WITHHELD_UNAUTHORISED = "m.unauthorised"
WITHHELD_UNAVAILABLE = "m.unavailable"
WITHHELD_NO_OLM = "m.no_olm"
WITHHELD_HISTORY_NOT_SHARED = "m.history_not_shared"
VALID_WITHHELD_CODES = frozenset(
    {
        WITHHELD_BLACKLISTED,
        WITHHELD_UNVERIFIED,
        WITHHELD_UNAUTHORISED,
        WITHHELD_UNAVAILABLE,
        WITHHELD_NO_OLM,
        WITHHELD_HISTORY_NOT_SHARED,
    }
)
VALID_TO_DEVICE_WITHHELD_CODES = VALID_WITHHELD_CODES - {WITHHELD_HISTORY_NOT_SHARED}

SUPPORTED_SECRET_NAMES = frozenset(
    {
        SECRET_MEGOLM_BACKUP_V1,
        SECRET_CROSS_SIGNING_MASTER,
        SECRET_CROSS_SIGNING_SELF_SIGNING,
        SECRET_CROSS_SIGNING_USER_SIGNING,
    }
)

# Cross-signing recovery policy/state
FORCE_OVERWRITE_SERVER_KEYS = True
DEVICE_SECRET_REQUEST_PENDING = "pending"
DEVICE_SECRET_REQUEST_FAILED = "failed"
DEVICE_SECRET_REQUEST_NOT_NEEDED = "not_needed"
DEVICE_SECRET_REQUEST_UNAVAILABLE = "unavailable"

# SAS verification negotiation
SAS_METHODS = [M_SAS_V1_METHOD]
SAME_USER_QR_METHODS = [
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
]
HASHES = ["sha256"]
MESSAGE_AUTHENTICATION_CODES = ["hkdf-hmac-sha256.v2", "hkdf-hmac-sha256"]
SHORT_AUTHENTICATION_STRING = ["decimal", "emoji"]

# Matrix SAS emoji table (64 entries, indexes are protocol-significant).
SAS_EMOJIS = [
    ("🐶", "Dog"),
    ("🐱", "Cat"),
    ("🦁", "Lion"),
    ("🐴", "Horse"),
    ("🦄", "Unicorn"),
    ("🐷", "Pig"),
    ("🐘", "Elephant"),
    ("🐰", "Rabbit"),
    ("🐼", "Panda"),
    ("🐓", "Rooster"),
    ("🐧", "Penguin"),
    ("🐢", "Turtle"),
    ("🐟", "Fish"),
    ("🐙", "Octopus"),
    ("🦋", "Butterfly"),
    ("🌷", "Flower"),
    ("🌳", "Tree"),
    ("🌵", "Cactus"),
    ("🍄", "Mushroom"),
    ("🌏", "Globe"),
    ("🌙", "Moon"),
    ("☁️", "Cloud"),
    ("🔥", "Fire"),
    ("🍌", "Banana"),
    ("🍎", "Apple"),
    ("🍓", "Strawberry"),
    ("🌽", "Corn"),
    ("🍕", "Pizza"),
    ("🎂", "Cake"),
    ("❤️", "Heart"),
    ("😀", "Smiley"),
    ("🤖", "Robot"),
    ("🎩", "Hat"),
    ("👓", "Glasses"),
    ("🔧", "Spanner"),
    ("🎅", "Santa"),
    ("👍", "Thumbs Up"),
    ("☂️", "Umbrella"),
    ("⌛", "Hourglass"),
    ("⏰", "Clock"),
    ("🎁", "Gift"),
    ("💡", "Light Bulb"),
    ("📕", "Book"),
    ("✏️", "Pencil"),
    ("📎", "Paperclip"),
    ("✂️", "Scissors"),
    ("🔒", "Lock"),
    ("🔑", "Key"),
    ("🔨", "Hammer"),
    ("☎️", "Telephone"),
    ("🏁", "Flag"),
    ("🚂", "Train"),
    ("🚲", "Bicycle"),
    ("✈️", "Aeroplane"),
    ("🚀", "Rocket"),
    ("🏆", "Trophy"),
    ("⚽", "Ball"),
    ("🎸", "Guitar"),
    ("🎺", "Trumpet"),
    ("🔔", "Bell"),
    ("⚓", "Anchor"),
    ("🎧", "Headphones"),
    ("📁", "Folder"),
    ("📌", "Pin"),
]

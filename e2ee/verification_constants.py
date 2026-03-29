from astrbot.api import logger

from ..constants import (
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    M_SAS_V1_METHOD,
)

# 尝试导入 vodozemac
try:
    from vodozemac import Curve25519PublicKey, EstablishedSas, Sas  # noqa: F401

    VODOZEMAC_SAS_AVAILABLE = True
except ImportError:
    Curve25519PublicKey = None
    EstablishedSas = None
    Sas = None
    VODOZEMAC_SAS_AVAILABLE = False
    logger.debug("vodozemac SAS 模块不可用，将使用简化实现")

# SAS 验证相关常量
SAS_METHODS = [M_SAS_V1_METHOD]
SAME_USER_QR_METHODS = [M_QR_CODE_SHOW_V1_METHOD, M_RECIPROCATE_V1_METHOD]
HASHES = ["sha256"]
MESSAGE_AUTHENTICATION_CODES = ["hkdf-hmac-sha256.v2", "hkdf-hmac-sha256"]
SHORT_AUTHENTICATION_STRING = ["decimal", "emoji"]

# SAS Emoji 列表 (Matrix 规范定义的 64 个 emoji)
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

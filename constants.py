"""
Matrix 常量集中定义，避免在代码中散落魔数/协议字符串。
"""

# 协议算法与格式
OLM_ALGO = "m.olm.v1.curve25519-aes-sha2"
# 历史或兼容用法（部分实现使用带 256 后缀）
OLM_ALGO_SHA256 = "m.olm.v1.curve25519-aes-sha2-256"
MEGOLM_ALGO = "m.megolm.v1.aes-sha2"
MEGOLM_BACKUP_ALGO = "m.megolm_backup.v1.curve25519-aes-sha2"
MEGOLM_BACKUP_INFO = "m.megolm_backup.v1"
MATRIX_HTML_FORMAT = "org.matrix.custom.html"

# 关系与线程常量
REL_TYPE_THREAD = "m.thread"

# 通用事件类型
M_ROOM_ENCRYPTED = "m.room.encrypted"
M_ROOM_KEY = "m.room_key"
M_ROOM_KEY_REQUEST = "m.room_key_request"
M_FORWARDED_ROOM_KEY = "m.forwarded_room_key"
M_ROOM_MEMBER = "m.room.member"
MEMBERSHIP_JOIN = "join"
MEMBERSHIP_INVITE = "invite"

# 设备密钥前缀
PREFIX_ED25519 = "ed25519:"
PREFIX_CURVE25519 = "curve25519:"
SIGNED_CURVE25519 = "signed_curve25519"

# SSSS / 账户数据类型
SSSS_DEFAULT_KEY = "m.secret_storage.default_key"
SSSS_KEY_PREFIX = "m.secret_storage.key."
SSSS_BACKUP_SECRET = "m.megolm_backup.v1"
DEHYDRATED_DEVICE_EVENT = "m.dehydrated_device"
MSC2697_DEHYDRATED_DEVICE_EVENT = "org.matrix.msc2697.dehydrated_device"

# 恢复密钥编码（Base58）
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RECOVERY_KEY_HDR_BYTE1 = 0x8B
RECOVERY_KEY_HDR_BYTE2 = 0x01
RECOVERY_KEY_TOTAL_LEN = 35  # 2B 头 + 32B 私钥 + 1B XOR 校验
RECOVERY_KEY_PRIV_LEN = 32
RECOVERY_KEY_MAC_TRUNCATED_LEN = 8

# 密钥派生/加密参数
HKDF_MEGOLM_BACKUP_INFO = b"m.megolm_backup.v1"
HKDF_KEY_MATERIAL_LEN = 80  # 32 (AES) + 32 (MAC) + 16 (IV)
AES_GCM_NONCE_LEN = 12
AES_CBC_IV_LEN = 16

# 默认数量/超时
DEFAULT_ONE_TIME_KEYS_COUNT = 50
DEFAULT_TYPING_TIMEOUT_MS = 5000

# 验证相关
KEY_AGREEMENT_PROTOCOLS = ["curve25519-hkdf-sha256"]
M_KEY_VERIFICATION_REQUEST = "m.key.verification.request"
M_KEY_VERIFICATION_READY = "m.key.verification.ready"
M_KEY_VERIFICATION_START = "m.key.verification.start"
M_KEY_VERIFICATION_ACCEPT = "m.key.verification.accept"
M_KEY_VERIFICATION_KEY = "m.key.verification.key"
M_KEY_VERIFICATION_MAC = "m.key.verification.mac"
M_KEY_VERIFICATION_DONE = "m.key.verification.done"
M_KEY_VERIFICATION_CANCEL = "m.key.verification.cancel"
M_SAS_V1_METHOD = "m.sas.v1"

# 验证信息前缀（用于 MAC/SAS info 文本）
INFO_PREFIX_SAS = "MATRIX_KEY_VERIFICATION_SAS|"
INFO_PREFIX_MAC = "MATRIX_KEY_VERIFICATION_MAC"

# 在线状态
PRESENCE_ONLINE = "online"
PRESENCE_OFFLINE = "offline"

# 协议和加密常量
CRYPTO_KEY_SIZE_32 = 32
AES_BLOCK_SIZE_16 = 16
MAC_TRUNCATED_BYTES_8 = 8
SAS_BYTES_LENGTH_6 = 6
SAS_EMOJI_COUNT_7 = 7

# 消息和数据处理常量
TEXT_TRUNCATE_LENGTH_50 = 50
ERROR_TRUNCATE_LENGTH_200 = 200
HTTP_ERROR_STATUS_400 = 400
RESPONSE_TRUNCATE_LENGTH_400 = 400

# 时间和网络常量
DEFAULT_TIMEOUT_MS_30000 = 30000
KEY_QUERY_TIMEOUT_MS_10000 = 10000

# 显示和格式化常量
DISPLAY_TRUNCATE_LENGTH_4 = 4
TXN_DISPLAY_LENGTH_8 = 8
DISPLAY_TRUNCATE_LENGTH_20 = 20

# 消息处理常量
MAX_PROCESSED_MESSAGES_1000 = 1000
TIMESTAMP_BUFFER_MS_1000 = 1000
GROUP_CHAT_MIN_MEMBERS_2 = 2

# 文件上传常量
# 默认最大上传文件大小 (10MB)，超过此大小将尝试压缩
DEFAULT_MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024
# 图片压缩最低质量
IMAGE_MIN_QUALITY = 30
# 图片压缩步进
IMAGE_QUALITY_STEP = 10
# 图片最大尺寸（宽或高的最大像素数）
IMAGE_MAX_DIMENSION = 2048

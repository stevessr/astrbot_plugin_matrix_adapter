"""Matrix encryption, key-management, and verification constants."""

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

# 秘密传输事件类型 (设备间秘密共享)
M_SECRET_REQUEST = "m.secret.request"
M_SECRET_SEND = "m.secret.send"

# 可共享的秘密名称
SECRET_MEGOLM_BACKUP_V1 = "m.megolm_backup.v1"
SECRET_CROSS_SIGNING_MASTER = "m.cross_signing.master"
SECRET_CROSS_SIGNING_SELF_SIGNING = "m.cross_signing.self_signing"
SECRET_CROSS_SIGNING_USER_SIGNING = "m.cross_signing.user_signing"

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
M_QR_CODE_SHOW_V1_METHOD = "m.qr_code.show.v1"
M_QR_CODE_SCAN_V1_METHOD = "m.qr_code.scan.v1"
M_RECIPROCATE_V1_METHOD = "m.reciprocate.v1"
QR_CODE_HEADER = b"MATRIX"
QR_CODE_VERSION = 0x02
QR_CODE_MODE_VERIFY_OTHER_USER = 0x00
QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER = 0x01
QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER = 0x02

# 验证信息前缀（用于 MAC/SAS info 文本）
INFO_PREFIX_SAS = "MATRIX_KEY_VERIFICATION_SAS|"
INFO_PREFIX_MAC = "MATRIX_KEY_VERIFICATION_MAC"

__all__ = [name for name in globals() if not name.startswith("_")]

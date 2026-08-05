"""Media security validation error classification."""


def _is_media_security_validation_error(err: Exception) -> bool:
    message = str(err)
    security_error_prefixes = (
        "Blocked media upload extension:",
        "Declared MIME type is not allowed:",
        "Sniffed MIME type is not allowed:",
        "Declared MIME does not match file signature:",
        "Declared MIME does not match file extension:",
        "File extension does not match file signature:",
    )
    return any(message.startswith(prefix) for prefix in security_error_prefixes)


__all__ = ["_is_media_security_validation_error"]

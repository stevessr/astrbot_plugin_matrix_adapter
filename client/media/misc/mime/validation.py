"""Media upload validation using MIME policy and signatures."""

import mimetypes


class MediaMimeValidationMixin:
    """Validate declared, extension-derived, and sniffed MIME types."""

    def _validate_media_upload_security(
        self,
        *,
        filename: str,
        declared_content_type: str,
        file_head: bytes,
    ) -> str:
        normalized_declared = self._normalize_mime_type(declared_content_type)
        extension = self._normalize_extension(filename)
        blocked_extensions = self._get_media_upload_blocked_extensions()
        if extension and (extension in blocked_extensions or "*" in blocked_extensions):
            raise ValueError(
                f"Blocked media upload extension: {extension} (file: {filename})"
            )

        allowed_rules = self._get_media_upload_allowed_mime_rules()
        if not self._mime_allowed_by_rules(normalized_declared, allowed_rules):
            raise ValueError(
                f"Declared MIME type is not allowed: {normalized_declared} (file: {filename})"
            )

        sniffed_mime = self._sniff_mime_from_bytes(file_head)
        extension_mime = self._normalize_mime_type(mimetypes.guess_type(filename)[0])
        strict_check = self._is_media_upload_strict_mime_check_enabled()

        if sniffed_mime and not self._mime_allowed_by_rules(
            sniffed_mime, allowed_rules
        ):
            raise ValueError(
                f"Sniffed MIME type is not allowed: {sniffed_mime} (file: {filename})"
            )

        if strict_check:
            if sniffed_mime and not self._is_mime_compatible(
                normalized_declared, sniffed_mime
            ):
                raise ValueError(
                    "Declared MIME does not match file signature: "
                    f"{normalized_declared} vs {sniffed_mime} (file: {filename})"
                )
            if (
                extension
                and extension_mime
                and not self._is_mime_compatible(normalized_declared, extension_mime)
            ):
                raise ValueError(
                    "Declared MIME does not match file extension: "
                    f"{normalized_declared} vs {extension_mime} (file: {filename})"
                )
            if (
                extension
                and extension_mime
                and sniffed_mime
                and not self._is_mime_compatible(extension_mime, sniffed_mime)
            ):
                raise ValueError(
                    "File extension does not match file signature: "
                    f"{extension_mime} vs {sniffed_mime} (file: {filename})"
                )

        if (
            normalized_declared == "application/octet-stream"
            and sniffed_mime
            and self._mime_allowed_by_rules(sniffed_mime, allowed_rules)
        ):
            return sniffed_mime
        if (
            normalized_declared == "application/octet-stream"
            and extension_mime
            and self._mime_allowed_by_rules(extension_mime, allowed_rules)
        ):
            return extension_mime
        return normalized_declared

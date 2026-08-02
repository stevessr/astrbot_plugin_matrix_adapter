"""File-signature MIME sniffing helpers."""

from pathlib import Path


class MediaMimeSniffingMixin:
    """Detect MIME types from file signatures and read file prefixes."""

    @staticmethod
    def _sniff_mime_from_bytes(data: bytes) -> str | None:
        if not data:
            return None

        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "image/webp"
        if data.startswith(b"BM"):
            return "image/bmp"
        if data.startswith((b"II*\x00", b"MM\x00*")):
            return "image/tiff"
        if data.startswith(b"%PDF-"):
            return "application/pdf"
        if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return "application/zip"
        if data.startswith((b"\x1f\x8b\x08",)):
            return "application/gzip"
        if data.startswith(b"OggS"):
            return "audio/ogg"
        if data.startswith(b"fLaC"):
            return "audio/flac"
        if data.startswith(b"ID3"):
            return "audio/mpeg"
        if len(data) > 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
            return "audio/mpeg"
        if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            return "audio/wav"
        if data[:4] == b"RIFF" and data[8:11] == b"AVI":
            return "video/x-msvideo"
        if len(data) >= 12 and data[4:8] == b"ftyp":
            # ISO BMFF family (MP4/HEIF/AVIF/etc.)
            # bytes[8:12] is major brand, then minor version, then compatible brands.
            # We scan early brand slots to avoid misclassifying AVIF as generic MP4.
            brand_bytes = [data[i : i + 4] for i in range(8, min(len(data), 64) - 3, 4)]
            if any(brand in {b"avif", b"avis"} for brand in brand_bytes):
                return "image/avif"
            if any(
                brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}
                for brand in brand_bytes
            ):
                return "image/heif"
            return "video/mp4"
        if data.startswith(b"\x1a\x45\xdf\xa3"):
            return "video/webm"

        stripped = data.lstrip()
        if stripped.startswith((b"{", b"[")):
            return "application/json"
        if stripped:
            text_sample = stripped[:200]
            printable = sum(
                1 for b in text_sample if b in (9, 10, 13) or 32 <= b <= 126
            )
            if printable / max(1, len(text_sample)) >= 0.95:
                return "text/plain"
        return None

    @staticmethod
    def _read_file_head(path: Path, size: int) -> bytes:
        with path.open("rb") as f:
            return f.read(size)

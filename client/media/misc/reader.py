"""Hashing file reader used by streamed media uploads."""

import hashlib
import io


class MediaHashingReaderMixin:
    """Expose an IO-compatible reader that tracks uploaded bytes."""

    class _HashingFileReader(io.IOBase):
        """IOBase-compatible file wrapper that hashes uploaded bytes."""

        def __init__(self, file_handle: io.BufferedReader):
            self._file_handle = file_handle
            self._hasher = hashlib.sha256()

        def read(self, size: int = -1) -> bytes:
            chunk = self._file_handle.read(size)
            if chunk:
                self._hasher.update(chunk)
            return chunk

        def readinto(self, b) -> int:
            reader = getattr(self._file_handle, "readinto", None)
            if callable(reader):
                n = reader(b)
                if n and n > 0:
                    self._hasher.update(memoryview(b)[:n])
                return n

            chunk = self._file_handle.read(len(b))
            if not chunk:
                return 0
            n = len(chunk)
            b[:n] = chunk
            self._hasher.update(chunk)
            return n

        def readline(self, size: int = -1) -> bytes:
            chunk = self._file_handle.readline(size)
            if chunk:
                self._hasher.update(chunk)
            return chunk

        def readable(self) -> bool:
            return True

        def seekable(self) -> bool:
            return self._file_handle.seekable()

        def writable(self) -> bool:
            return False

        def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
            return self._file_handle.seek(offset, whence)

        def tell(self) -> int:
            return self._file_handle.tell()

        def fileno(self) -> int:
            return self._file_handle.fileno()

        @property
        def closed(self) -> bool:
            return self._file_handle.closed

        def close(self) -> None:
            self._file_handle.close()

        def hexdigest(self) -> str:
            return self._hasher.hexdigest()

        def __getattr__(self, name: str):
            return getattr(self._file_handle, name)

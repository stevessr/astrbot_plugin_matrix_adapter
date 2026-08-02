class CryptoStorePersistCompatibilityMixin:
    @classmethod
    def _json_filename_resolver(cls, record_key: str) -> str:
        return cls._LEGACY_FILES.get(record_key, f"{record_key}.json")

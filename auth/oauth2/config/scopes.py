"""OAuth2 scope normalization."""


class MatrixOAuth2ConfigScopesMixin:
    def _normalize_scopes(self, scopes: list | None) -> list[str]:
        normalized_scopes: list[str] = []
        seen: set[str] = set()
        effective_device_id = self.device_id

        raw_scopes = scopes if scopes is not None else list(self._DEFAULT_SCOPES)
        for scope in raw_scopes:
            if not isinstance(scope, str):
                continue

            normalized_scope = scope.strip()
            if not normalized_scope:
                continue

            if normalized_scope == self._LEGACY_API_SCOPE:
                normalized_scope = self._STABLE_API_SCOPE

            if normalized_scope.startswith(self._LEGACY_DEVICE_SCOPE_PREFIX):
                if not effective_device_id:
                    effective_device_id = self._normalize_device_id(
                        normalized_scope.removeprefix(self._LEGACY_DEVICE_SCOPE_PREFIX)
                    )
                continue

            if normalized_scope.startswith(self._STABLE_DEVICE_SCOPE_PREFIX):
                if not effective_device_id:
                    effective_device_id = self._normalize_device_id(
                        normalized_scope.removeprefix(self._STABLE_DEVICE_SCOPE_PREFIX)
                    )
                continue

            if normalized_scope not in seen:
                normalized_scopes.append(normalized_scope)
                seen.add(normalized_scope)

        self.device_id = self._normalize_device_id(effective_device_id)
        device_scope = f"{self._STABLE_DEVICE_SCOPE_PREFIX}{self._ensure_device_id()}"
        if device_scope not in seen:
            normalized_scopes.append(device_scope)

        return normalized_scopes

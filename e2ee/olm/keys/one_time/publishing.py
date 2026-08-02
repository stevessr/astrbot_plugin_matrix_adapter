"""One-time-key publication state updates."""


class OlmMachineOneTimeKeyPublishingMixin:
    def mark_keys_as_published(self):
        """标记一次性密钥为已发布"""
        if self._account:
            self._account.mark_keys_as_published()
            self._is_new_account = False
            self._save_account()

from astrbot.api import logger

from .olm_machine_types import Account


class OlmMachineAccountMixin:
    def _init_account(self):
        """初始化或加载 Olm 账户"""
        # 如果 device_id 变化了，需要创建新账户
        if self.store.device_id_changed:
            logger.info("由于 device_id 变化，创建新的 Olm 账户")
            self._create_new_account()
            return

        pickle = self.store.get_account_pickle()

        if pickle:
            # 从 pickle 恢复账户
            try:
                self._account = Account.from_pickle(pickle, self._pickle_key)
                self._is_new_account = False
                logger.info("从存储恢复 Olm 账户")

                logger.debug("账户 curve25519 密钥已从存储加载")
            except Exception as e:
                logger.warning(f"恢复 Olm 账户失败（可能是密钥不匹配或数据损坏）：{e}")
                logger.info("将创建新的 Olm 账户")
                # 删除损坏的账户记录
                try:
                    self.store.clear_account_pickle()
                    logger.info("已删除损坏的账户记录")
                except Exception as cleanup_e:
                    logger.warning(f"删除损坏文件失败：{cleanup_e}")
                self._create_new_account()
        else:
            self._create_new_account()

    def _create_new_account(self):
        """创建新的 Olm 账户"""
        self._account = Account()
        self._is_new_account = True
        self._save_account()
        logger.info("创建了新的 Olm 账户")
        logger.debug("新账户 curve25519 密钥已生成")

    def _save_account(self):
        """保存 Olm 账户到存储"""
        if self._account:
            pickle = self._account.pickle(self._pickle_key)
            self.store.save_account_pickle(pickle)

    # ========== 设备密钥 ==========

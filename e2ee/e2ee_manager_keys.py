"""
E2EE Manager key upload helpers.
"""

from astrbot.api import logger

from ..constants import MEGOLM_ALGO, OLM_ALGO, SIGNED_CURVE25519


class E2EEManagerKeysMixin:
    async def _upload_device_keys(self):
        """上传设备密钥到服务器"""
        if not self._olm:
            logger.warning("OlmMachine 未初始化，跳过设备密钥上传")
            return

        try:
            current_key_counts = await self._get_server_key_counts()
            server_otk_count = current_key_counts.get(SIGNED_CURVE25519, 0)
            logger.info(f"服务器上当前一次性密钥数量：{server_otk_count}")

            device_keys = None
            if self._olm.is_new_account:
                device_keys = self._olm.get_device_keys()
                logger.info(
                    f"新账户，准备上传设备密钥：device_id={device_keys.get('device_id')}"
                )
                algorithms = device_keys.get("algorithms", [])
                logger.info(f"支持的加密算法：{algorithms}")
                keys_info = list(device_keys.get("keys", {}).keys())
                logger.info(f"密钥列表：{keys_info}")

                signatures = device_keys.get("signatures", {})
                logger.info(f"签名用户：{list(signatures.keys())}")

                required_algos = [OLM_ALGO, MEGOLM_ALGO]
                missing_algos = [
                    algo for algo in required_algos if algo not in algorithms
                ]
                if missing_algos:
                    logger.error(f"缺少必要的加密算法：{missing_algos}")
                else:
                    logger.info("设备密钥包含所有必要的加密算法")
            else:
                logger.info("账户已从存储恢复，跳过设备密钥上传（只补充一次性密钥）")

            from ..constants import DEFAULT_ONE_TIME_KEYS_COUNT

            keys_to_generate = max(0, DEFAULT_ONE_TIME_KEYS_COUNT - server_otk_count)
            one_time_keys = {}
            if keys_to_generate > 0:
                one_time_keys = self._olm.generate_one_time_keys(keys_to_generate)
                logger.info(f"生成了 {len(one_time_keys)} 个一次性密钥（补充）")
            else:
                logger.info(
                    f"服务器上已有足够的一次性密钥（{server_otk_count}），跳过生成"
                )

            fallback_keys = {}
            if self._olm.get_unpublished_fallback_key_count() == 0:
                fallback_keys = self._olm.generate_fallback_key()
                if fallback_keys:
                    logger.info("生成了 fallback key")

            if device_keys or one_time_keys or fallback_keys:
                logger.info("正在上传密钥到服务器...")
                response = await self.client.upload_keys(
                    device_keys=device_keys,
                    one_time_keys=one_time_keys if one_time_keys else None,
                    fallback_keys=fallback_keys if fallback_keys else None,
                )
                if "error" in response or "errcode" in response:
                    logger.error(f"密钥上传失败：{response}")
                    return

                self._olm.mark_keys_as_published()

                counts = response.get("one_time_key_counts", {})
                logger.info(f"密钥已成功上传，一次性密钥数量：{counts}")

                if device_keys:
                    try:
                        verify_response = await self.client.query_keys(
                            {self.user_id: []}
                        )
                        my_devices = verify_response.get("device_keys", {}).get(
                            self.user_id, {}
                        )
                        if self.device_id in my_devices:
                            my_device_info = my_devices[self.device_id]
                            my_keys = my_device_info.get("keys", {})
                            logger.info(
                                f"✅ 验证成功：服务器已确认设备 {self.device_id} 的密钥"
                            )
                            logger.info(f"服务器上的密钥：{list(my_keys.keys())}")
                            signatures = my_device_info.get("signatures", {})
                            logger.info(f"服务器上的签名：{signatures}")
                        else:
                            logger.error(
                                f"❌ 验证失败：服务器没有设备 {self.device_id} 的密钥！"
                            )
                            logger.error(
                                f"服务器上的设备列表：{list(my_devices.keys())}"
                            )
                    except Exception as verify_e:
                        logger.warning(f"验证设备密钥失败：{verify_e}")
            else:
                logger.info("没有需要上传的密钥")

        except Exception as e:
            import traceback

            logger.error(f"上传设备密钥失败：{e}")
            logger.error(f"异常详情：{traceback.format_exc()}")

    async def _get_server_key_counts(self) -> dict:
        """获取服务器上的密钥数量"""
        try:
            response = await self.client.upload_keys()
            return response.get("one_time_key_counts", {})
        except Exception as e:
            logger.warning(f"获取服务器密钥数量失败：{e}")
            return {}

    async def ensure_sufficient_one_time_keys(
        self, server_counts: dict | None = None
    ) -> None:
        """Proactively top up one-time keys when server count is low."""
        if not self._olm or not self._initialized:
            return

        try:
            counts = server_counts if isinstance(server_counts, dict) else None
            if counts is None:
                counts = await self._get_server_key_counts()

            server_otk_count = int(counts.get(SIGNED_CURVE25519, 0))

            from ..constants import DEFAULT_ONE_TIME_KEYS_COUNT

            # 使用配置的阈值比例
            threshold_ratio = getattr(self, "otk_threshold_ratio", 33) / 100.0
            min_threshold = max(1, int(DEFAULT_ONE_TIME_KEYS_COUNT * threshold_ratio))
            if server_otk_count >= min_threshold:
                return

            import time

            now = time.monotonic()
            last_ts = getattr(self, "_last_otk_maintenance_ts", 0.0)
            # 使用配置的维护间隔
            maintenance_interval = getattr(self, "key_maintenance_interval", 60)
            if now - last_ts < maintenance_interval:
                return
            self._last_otk_maintenance_ts = now

            keys_to_generate = max(0, DEFAULT_ONE_TIME_KEYS_COUNT - server_otk_count)
            one_time_keys = {}
            if keys_to_generate > 0:
                one_time_keys = self._olm.generate_one_time_keys(keys_to_generate)

            fallback_keys = {}
            if self._olm.get_unpublished_fallback_key_count() == 0:
                fallback_keys = self._olm.generate_fallback_key()

            if not one_time_keys and not fallback_keys:
                return

            response = await self.client.upload_keys(
                one_time_keys=one_time_keys if one_time_keys else None,
                fallback_keys=fallback_keys if fallback_keys else None,
            )

            if "error" in response or "errcode" in response:
                logger.warning(f"自动补充一次性密钥失败：{response}")
                return

            self._olm.mark_keys_as_published()
            updated_counts = response.get("one_time_key_counts", {})
            logger.info(
                f"已主动补充一次性密钥：{server_otk_count} -> "
                f"{updated_counts.get(SIGNED_CURVE25519, server_otk_count)}"
            )
        except Exception as e:
            logger.warning(f"主动补充一次性密钥失败：{e}")

from concurrent.futures import Future, wait

from astrbot.api import logger


class CryptoStorePersistQueueMixin:
    def _on_persist_future_done(
        self,
        future: Future,
        *,
        operation: str,
        record_key: str,
    ) -> None:
        try:
            future.result()
        except Exception as e:
            logger.error(f"{operation} 加密存储记录失败 {record_key}: {e}")
        finally:
            with self._persist_futures_lock:
                self._persist_futures.discard(future)
            self._persist_slots.release()

    def _submit_persist_job(
        self,
        operation: str,
        record_key: str,
        job,
        *job_args,
    ) -> None:
        if self._initializing or self._closed:
            job(*job_args)
            return

        acquired = self._persist_slots.acquire(
            timeout=self._PERSIST_QUEUE_WAIT_TIMEOUT_SECONDS
        )
        if not acquired:
            logger.warning(
                "E2EE storage queue is saturated; falling back to synchronous write "
                f"(op={operation}, key={record_key})"
            )
            job(*job_args)
            return

        try:
            future = self._persist_executor.submit(job, *job_args)
            with self._persist_futures_lock:
                self._persist_futures.add(future)
            future.add_done_callback(
                lambda done: self._on_persist_future_done(
                    done, operation=operation, record_key=record_key
                )
            )
        except Exception as e:
            self._persist_slots.release()
            logger.warning(
                f"提交加密存储任务失败 {operation}/{record_key}，回退同步写入：{e}"
            )
            job(*job_args)

    def flush(self, timeout: float | None = None) -> bool:
        if timeout is None:
            timeout = self._PERSIST_FLUSH_TIMEOUT_SECONDS
        with self._persist_futures_lock:
            pending_futures = list(self._persist_futures)
        if not pending_futures:
            return True
        _, not_done = wait(pending_futures, timeout=timeout)
        if not_done:
            logger.warning(
                f"E2EE storage flush timed out with {len(not_done)} pending jobs"
            )
            return False
        return True

    def close(self, timeout: float | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        flushed = self.flush(timeout=timeout)
        if flushed:
            self._persist_executor.shutdown(wait=True, cancel_futures=False)
        else:
            self._persist_executor.shutdown(wait=False, cancel_futures=True)

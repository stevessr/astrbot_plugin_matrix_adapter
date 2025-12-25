"""
Matrix HTTP Client - Direct implementation without matrix-nio
Implements the Matrix Client-Server API using aiohttp
"""

import json
import os
from typing import Any

import aiohttp

from astrbot.api import logger

from ..constants import (
    DEFAULT_TIMEOUT_MS_30000,
    ERROR_TRUNCATE_LENGTH_200,
    HTTP_ERROR_STATUS_400,
    KEY_QUERY_TIMEOUT_MS_10000,
    RESPONSE_TRUNCATE_LENGTH_400,
)


class MatrixAPIError(Exception):
    """Matrix API Error"""

    def __init__(self, status: int, data: dict | str, message: str):
        self.status = status
        self.data = data
        self.message = message
        super().__init__(message)


class MatrixHTTPClient:
    """
    Low-level HTTP client for Matrix C-S API
    Does not depend on matrix-nio
    """

    def __init__(self, homeserver: str):
        """
        Initialize Matrix HTTP client

        Args:
            homeserver: Matrix homeserver URL (e.g., https://matrix.org)
        """
        self.homeserver = homeserver.rstrip("/")
        self.access_token: str | None = None
        self.user_id: str | None = None
        self.device_id: str | None = None
        self.session: aiohttp.ClientSession | None = None
        self._next_batch: str | None = None

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()

    async def close(self):
        """Close the HTTP session"""
        if self.session and not self.session.closed:
            await self.session.close()

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for authenticated requests"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    async def _request(
        self,
        method: str,
        endpoint: str,
        data: dict | None = None,
        params: dict | None = None,
        authenticated: bool = True,
    ) -> dict[str, Any]:
        """
        Make HTTP request to Matrix server

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., /_matrix/client/v3/login)
            data: JSON data for request body
            params: URL query parameters
            authenticated: Whether to include access token

        Returns:
            Response JSON data

        Raises:
            Exception: On HTTP errors
        """
        await self._ensure_session()

        url = f"{self.homeserver}{endpoint}"
        headers = (
            self._get_headers()
            if authenticated
            else {
                "Content-Type": "application/json",
                "User-Agent": "AstrBot Matrix Client/1.0",
            }
        )

        try:
            async with self.session.request(
                method, url, json=data, params=params, headers=headers
            ) as response:
                # 检查响应状态
                if response.status >= HTTP_ERROR_STATUS_400:
                    # 尝试获取错误信息，但处理非 JSON 响应
                    try:
                        response_data = await response.json()
                        error_code = response_data.get("errcode", "UNKNOWN")
                        error_msg = response_data.get("error", "Unknown error")
                        error_detail = f"Matrix API error: {error_code} - {error_msg} (status: {response.status})"
                        # Raise structured error
                        raise MatrixAPIError(
                            response.status, response_data, error_detail
                        )
                    except MatrixAPIError:
                        raise
                    except Exception:
                        # 如果不是 JSON 响应，获取文本内容
                        content_type = response.headers.get("content-type", "").lower()
                        if "text/html" in content_type:
                            error_detail = f"Matrix API error: HTML error page returned (status: {response.status})"
                            raise MatrixAPIError(
                                response.status, "HTML error page", error_detail
                            )
                        else:
                            text = await response.text()
                            error_detail = f"Matrix API error: Non-JSON response (status: {response.status}): {text[:ERROR_TRUNCATE_LENGTH_200]}"
                            raise MatrixAPIError(response.status, text, error_detail)

                    # This part is now unreachable due to raise above, but keeping structure clean
                    # raise Exception(error_detail)

                # 对于成功响应，尝试解析 JSON
                try:
                    response_data = await response.json()
                except Exception:
                    # 如果不是 JSON 响应，获取文本内容
                    content_type = response.headers.get("content-type", "").lower()
                    if "text/html" in content_type:
                        raise Exception(
                            f"Matrix API error: HTML response instead of JSON (status: {response.status})"
                        )
                    else:
                        text = await response.text()
                        raise Exception(
                            f"Matrix API error: Non-JSON response (status: {response.status}): {text[:ERROR_TRUNCATE_LENGTH_200]}"
                        )

                return response_data

        except aiohttp.ClientError as e:
            logger.error(f"Matrix HTTP request failed: {e}")
            raise

    async def get_login_flows(self) -> dict[str, Any]:
        """
        Get supported login flows from the server

        Returns:
            Response with supported login flows
        """
        return await self._request(
            "GET", "/_matrix/client/v3/login", authenticated=False
        )

    async def login_password(
        self,
        user_id: str,
        password: str,
        device_name: str = "AstrBot",
        device_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Login with password

        Args:
            user_id: Matrix user ID
            password: User password
            device_name: Device display name
            device_id: Optional device ID to reuse

        Returns:
            Login response with access_token, device_id, etc.
        """
        data = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": user_id},
            "password": password,
            "initial_device_display_name": device_name,
        }
        if device_id:
            data["device_id"] = device_id

        try:
            response = await self._request(
                "POST", "/_matrix/client/v3/login", data=data, authenticated=False
            )

            self.access_token = response.get("access_token")
            self.user_id = response.get("user_id")
            self.device_id = response.get("device_id")

            return response
        except Exception as e:
            error_msg = str(e)
            # Provide better diagnostics for HTML error pages
            if "HTML error page" in error_msg or "status: 403" in error_msg:
                logger.error(
                    f"Login failed with HTML error page. This usually means:\n"
                    f"  1. The homeserver URL is incorrect (currently: {self.homeserver})\n"
                    f"  2. The server URL points to a web interface, not the API\n"
                    f"  3. The /login endpoint is disabled or requires additional authentication\n"
                    f"  4. There's a reverse proxy/firewall blocking API access\n"
                    f"\n"
                    f"Attempted URL: {self.homeserver}/_matrix/client/v3/login\n"
                    f"User ID: {user_id}\n"
                    f"\n"
                    f"Troubleshooting:\n"
                    f"  - Verify your homeserver URL is correct (should end in the domain, e.g., https://matrix.example.com)\n"
                    f"  - Try accessing {self.homeserver}/_matrix/client/versions in a browser\n"
                    f"  - Check if your server requires a different login method (SSO, OAuth2, etc.)\n"
                    f"  - Consult your server administrator about password login availability"
                )
            raise

    def restore_login(
        self, user_id: str, access_token: str, device_id: str | None = None
    ):
        """
        Restore login session with access token

        Args:
            user_id: Matrix user ID
            access_token: Access token from previous login
            device_id: Device ID (optional)
        """
        self.user_id = user_id
        self.access_token = access_token
        self.device_id = device_id

    async def whoami(self) -> dict[str, Any]:
        """
        Get information about the current user

        Returns:
            User information including user_id and device_id
        """
        return await self._request("GET", "/_matrix/client/v3/account/whoami")

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh access token using a refresh token

        Args:
            refresh_token: Refresh token from previous login

        Returns:
            Response with new access_token and optionally a new refresh_token
        """
        endpoint = "/_matrix/client/v3/refresh"
        data = {"refresh_token": refresh_token}

        response = await self._request("POST", endpoint, data=data, authenticated=False)

        # Update client with new access token
        if "access_token" in response:
            self.access_token = response["access_token"]

        return response

    async def sync(
        self,
        since: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_MS_30000,
        full_state: bool = False,
        filter_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Sync with the Matrix server

        Args:
            since: Sync batch token from previous sync
            timeout: Timeout in milliseconds
            full_state: Whether to return full state
            filter_id: Filter ID for filtering events

        Returns:
            Sync response
        """
        params = {"timeout": timeout}
        if since:
            params["since"] = since
        if full_state:
            params["full_state"] = "true"
        if filter_id:
            params["filter"] = filter_id

        response = await self._request("GET", "/_matrix/client/v3/sync", params=params)

        # Log to_device events
        to_device = response.get("to_device", {}).get("events", [])
        if to_device:
            logger.info(
                f"SYNC: Received {len(to_device)} to_device events: {[e.get('type') for e in to_device]}"
            )

        # Store next_batch for future syncs
        self._next_batch = response.get("next_batch")

        return response

    async def send_message(
        self, room_id: str, msg_type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Send a message to a room

        Args:
            room_id: Room ID
            msg_type: Message type (e.g., m.room.message)
            content: Message content

        Returns:
            Send response with event_id
        """
        import time

        txn_id = f"{int(time.time() * 1000)}_{id(content)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/{msg_type}/{txn_id}"
        return await self._request("PUT", endpoint, data=content)

    # NOTE: send_to_device is defined later with an optional txn_id parameter.
    # The detailed implementation (including diagnostics) is implemented below
    # to avoid duplicate definitions.

    async def send_room_event(
        self, room_id: str, event_type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Send a custom event to a room

        Args:
            room_id: Room ID
            event_type: Event type (e.g., m.key.verification.request)
            content: Event content

        Returns:
            Send response with event_id
        """
        import time

        txn_id = f"txn_{int(time.time() * 1000)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}"
        return await self._request("PUT", endpoint, data=content)

    async def upload_file(
        self, data: bytes, content_type: str, filename: str
    ) -> dict[str, Any]:
        """
        Upload a file to the Matrix media repository

        Args:
            data: File data as bytes
            content_type: MIME type
            filename: Filename

        Returns:
            Upload response with content_uri
        """
        await self._ensure_session()

        url = f"{self.homeserver}/_matrix/media/v3/upload"
        headers = {
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.access_token}",
            "User-Agent": "AstrBot Matrix Client/1.0",
        }
        params = {"filename": filename}

        async with self.session.post(
            url, data=data, headers=headers, params=params
        ) as response:
            response_data = await response.json()

            if response.status >= HTTP_ERROR_STATUS_400:
                error_code = response_data.get("errcode", "UNKNOWN")
                error_msg = response_data.get("error", "Unknown error")
                raise Exception(
                    f"Matrix media upload error: {error_code} - {error_msg}"
                )

            return response_data

    async def get_media_config(self) -> dict[str, Any]:
        """
        获取 Matrix 媒体服务器配置

        返回服务器的媒体配置，包括最大上传文件大小。
        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixmediav3config

        Returns:
            包含 m.upload.size 等配置的字典
        """
        await self._ensure_session()

        # 尝试多个 API 端点
        endpoints = [
            "/_matrix/client/v1/media/config",  # 新的认证媒体 API
            "/_matrix/media/v3/config",
            "/_matrix/media/r0/config",
        ]

        for endpoint in endpoints:
            try:
                url = f"{self.homeserver}{endpoint}"
                headers = {
                    "Authorization": f"Bearer {self.access_token}",
                    "User-Agent": "AstrBot Matrix Client/1.0",
                }

                async with self.session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.json()
            except Exception as e:
                logger.debug(f"获取媒体配置失败 ({endpoint}): {e}")
                continue

        # 如果所有端点都失败，返回空字典
        logger.warning("无法获取 Matrix 媒体服务器配置，将使用默认值")
        return {}

    async def download_file(self, mxc_url: str) -> bytes:
        """
        Download a file from the Matrix media repository
        按照 Matrix spec 正确实现媒体下载

        参考：https://spec.matrix.org/latest/client-server-api/#get_matrixmediav3downloadservernamemediaid

        Args:
            mxc_url: MXC URL (mxc://server/media_id)

        Returns:
            File data as bytes
        """
        await self._ensure_session()

        # Parse MXC URL
        if not mxc_url.startswith("mxc://"):
            raise ValueError(f"Invalid MXC URL: {mxc_url}")

        parts = mxc_url[6:].split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid MXC URL format: {mxc_url}")

        server_name, media_id = parts

        # 按照 Matrix spec，所有媒体下载都通过用户的 homeserver
        # 不管媒体来自哪个服务器，都使用认证请求
        # 参考：https://spec.matrix.org/latest/client-server-api/#id429

        # Try multiple download strategies
        # 1. 通过用户 homeserver 代理下载（需要认证）
        # 2. 直接从源服务器下载（可能不需要认证）
        # 3. 缩略图作为最后手段

        # Strategy 1: 通过用户 homeserver 代理下载
        proxy_endpoints = [
            # 新的认证媒体 API (推荐)
            f"/_matrix/client/v1/media/download/{server_name}/{media_id}",
            # 传统 API
            f"/_matrix/media/v3/download/{server_name}/{media_id}",
            f"/_matrix/media/r0/download/{server_name}/{media_id}",
            # 带重定向参数
            f"/_matrix/media/v3/download/{server_name}/{media_id}?allow_redirect=true",
            f"/_matrix/media/r0/download/{server_name}/{media_id}?allow_redirect=true",
        ]

        # Strategy 2: 直接从源服务器下载
        direct_endpoints = [
            f"https://{server_name}/_matrix/media/v3/download/{server_name}/{media_id}",
            f"https://{server_name}/_matrix/media/r0/download/{server_name}/{media_id}",
            f"https://{server_name}/_matrix/media/v3/download/{server_name}/{media_id}?allow_redirect=true",
            f"https://{server_name}/_matrix/media/r0/download/{server_name}/{media_id}?allow_redirect=true",
        ]

        # Strategy 3: 尝试公开访问端点（不需要认证）
        public_endpoints = [
            f"https://{server_name}/_matrix/media/v1/download/{server_name}/{media_id}",
            f"https://{server_name}/_matrix/media/v1/download/{server_name}/{media_id}?allow_redirect=true",
        ]

        all_endpoints = (
            [(url, True) for url in proxy_endpoints]
            + [(url, False) for url in direct_endpoints]
            + [(url, False) for url in public_endpoints]
        )

        last_error = None
        last_status = None

        for endpoint_info in all_endpoints:
            if isinstance(endpoint_info, tuple):
                endpoint, use_auth = endpoint_info
                if use_auth:
                    url = f"{self.homeserver}{endpoint}"
                else:
                    url = endpoint  # 直接使用完整的 URL
            else:
                # 兼容旧格式
                endpoint = endpoint_info
                url = f"{self.homeserver}{endpoint}"
                use_auth = True

            # 根据策略决定是否使用认证
            headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
            if use_auth and self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"

            # 添加调试日志
            auth_status = (
                "with auth" if use_auth and self.access_token else "without auth"
            )
            logger.debug(f"Downloading from {url} {auth_status}")

            # 记录详细的下载策略
            logger.info(
                f"🎯 Attempting download from {url} {auth_status} (strategy: {'proxy' if use_auth else 'direct'})"
            )

            try:
                logger.debug(f"Downloading media from: {url}")
                async with self.session.get(
                    url, headers=headers, allow_redirects=True
                ) as response:
                    last_status = response.status
                    if response.status == 200:
                        logger.debug(
                            f"✅ Successfully downloaded media from {endpoint}"
                        )
                        return await response.read()
                    elif response.status == 404:
                        logger.debug(f"Got 404 on {endpoint}, trying next endpoint...")
                        last_error = f"Media not found: {response.status}"
                        continue
                    elif response.status == 403:
                        # 403 通常意味着认证问题或权限问题
                        logger.warning(
                            f"Got 403 on {endpoint} (auth problem or private media)"
                        )
                        last_error = f"Access denied: {response.status}"
                        continue
                    else:
                        last_error = f"HTTP {response.status}"
                        logger.debug(f"Got status {response.status} from {endpoint}")
            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.debug(f"Network error downloading from {endpoint}: {e}")
                continue
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Exception downloading from {endpoint}: {e}")
                continue

        # 所有端点都失败了，尝试缩略图作为最后手段
        if last_status in [403, 404]:
            logger.debug("Trying thumbnail endpoints as fallback...")
            thumbnail_endpoints = [
                # 新的认证媒体 API
                f"/_matrix/client/v1/media/thumbnail/{server_name}/{media_id}?width=800&height=600",
                # 传统 API
                f"/_matrix/media/v3/thumbnail/{server_name}/{media_id}?width=800&height=600",
                f"/_matrix/media/r0/thumbnail/{server_name}/{media_id}?width=800&height=600",
            ]

            for endpoint in thumbnail_endpoints:
                url = f"{self.homeserver}{endpoint}"
                headers = {"User-Agent": "AstrBot Matrix Client/1.0"}
                if self.access_token:
                    headers["Authorization"] = f"Bearer {self.access_token}"

                try:
                    async with self.session.get(
                        url, headers=headers, allow_redirects=True
                    ) as response:
                        if response.status == 200:
                            logger.info("✅ Downloaded thumbnail instead of full media")
                            return await response.read()
                except Exception:
                    continue

        # If all attempts failed, raise the last error
        error_msg = f"Matrix media download error: {last_error} (last status: {last_status}) for {mxc_url}"
        logger.error(error_msg)
        raise Exception(error_msg)

    async def join_room(self, room_id: str) -> dict[str, Any]:
        """
        Join a room

        Args:
            room_id: Room ID or alias

        Returns:
            Join response with room_id
        """
        endpoint = f"/_matrix/client/v3/join/{room_id}"
        return await self._request("POST", endpoint, data={})

    async def leave_room(self, room_id: str) -> dict[str, Any]:
        """
        Leave a room

        Args:
            room_id: Room ID

        Returns:
            Leave response
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/leave"
        return await self._request("POST", endpoint, data={})

    async def get_global_account_data(self, type: str) -> dict[str, Any]:
        """
        Get user global account data

        Args:
            type: Account data type (e.g., m.direct)

        Returns:
            Account data content
        """
        # Ensure user_id is set (it should be after login)
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")

        endpoint = f"/_matrix/client/v3/user/{self.user_id}/account_data/{type}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            # Return empty dict if not found (404)
            return {}

    async def get_room_members(self, room_id: str) -> dict[str, Any]:
        """
        Get room members

        Args:
            room_id: Room ID

        Returns:
            Room members data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/members"
        return await self._request("GET", endpoint)

    async def set_display_name(self, display_name: str) -> dict[str, Any]:
        """
        Set user display name

        Args:
            display_name: New display name

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/profile/{self.user_id}/displayname"
        return await self._request("PUT", endpoint, data={"displayname": display_name})

    async def get_display_name(self, user_id: str) -> str:
        """
        Get user display name

        Args:
            user_id: Matrix user ID

        Returns:
            Display name
        """
        endpoint = f"/_matrix/client/v3/profile/{user_id}/displayname"
        response = await self._request("GET", endpoint, authenticated=False)
        return response.get("displayname", user_id)

    async def get_avatar_url(self, user_id: str) -> str | None:
        """
        Get user avatar URL

        Args:
            user_id: Matrix user ID

        Returns:
            Avatar URL (mxc:// format) or None
        """
        endpoint = f"/_matrix/client/v3/profile/{user_id}/avatar_url"
        try:
            response = await self._request("GET", endpoint, authenticated=False)
            return response.get("avatar_url")
        except Exception:
            return None

    async def room_messages(
        self,
        room_id: str,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict[str, Any]:
        """
        Get messages from a room

        Args:
            room_id: Room ID
            from_token: Token to start from
            to_token: Token to end at
            direction: Direction to paginate ('b' for backwards, 'f' for forwards)
            limit: Maximum number of events to return

        Returns:
            Response with chunk of events and pagination tokens
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/messages"
        params = {
            "dir": direction,
            "limit": limit,
        }
        if from_token:
            params["from"] = from_token
        if to_token:
            params["to"] = to_token

        return await self._request("GET", endpoint, params=params)

    async def get_joined_rooms(self) -> list[str]:
        """
        Get list of joined room IDs

        Returns:
            List of room IDs
        """
        response = await self._request("GET", "/_matrix/client/v3/joined_rooms")
        return response.get("joined_rooms", [])

    async def edit_message(
        self,
        room_id: str,
        original_event_id: str,
        new_content: dict[str, Any],
        msg_type: str = "m.text",
    ) -> dict[str, Any]:
        """
        Edit an existing message

        Args:
            room_id: Room ID
            original_event_id: Event ID of the original message
            new_content: New message content (should include 'body')
            msg_type: Message type (default: m.text)

        Returns:
            Send response with event_id
        """
        import time

        txn_id = f"{int(time.time() * 1000)}_{id(new_content)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn_id}"

        # Construct edit content according to Matrix spec
        content = {
            "msgtype": msg_type,
            "body": f"* {new_content.get('body', '')}",  # Fallback for clients that don't support edits
            "m.new_content": {
                "msgtype": msg_type,
                "body": new_content.get("body", ""),
                **{
                    k: v for k, v in new_content.items() if k not in ["body", "msgtype"]
                },
            },
            "m.relates_to": {"rel_type": "m.replace", "event_id": original_event_id},
        }

        return await self._request("PUT", endpoint, data=content)

    async def get_devices(self) -> dict[str, Any]:
        """
        Get the list of devices for the current user

        Returns:
            List of devices with their information
        """
        endpoint = "/_matrix/client/v3/devices"

        return await self._request("GET", endpoint)

    async def get_device(self, device_id: str) -> dict[str, Any]:
        """
        Get information about a specific device

        Args:
            device_id: The device ID to query

        Returns:
            Device information
        """
        endpoint = f"/_matrix/client/v3/devices/{device_id}"

        return await self._request("GET", endpoint)

    async def update_device(
        self, device_id: str, display_name: str | None = None
    ) -> dict[str, Any]:
        """
        Update device information

        Args:
            device_id: The device ID to update
            display_name: New display name for the device

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/devices/{device_id}"

        data = {}
        if display_name is not None:
            data["display_name"] = display_name

        return await self._request("PUT", endpoint, data=data)

    async def delete_device(
        self, device_id: str, auth: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Delete a device

        Args:
            device_id: The device ID to delete
            auth: Authentication data (if required)

        Returns:
            Empty dict on success or auth flow information
        """
        endpoint = f"/_matrix/client/v3/devices/{device_id}"

        data = {}
        if auth:
            data["auth"] = auth

        return await self._request("DELETE", endpoint, data=data)

    async def set_typing(
        self, room_id: str, typing: bool = True, timeout: int = DEFAULT_TIMEOUT_MS_30000
    ) -> dict[str, Any]:
        """
        Set typing status in a room

        Args:
            room_id: Room ID
            typing: Whether the user is typing
            timeout: Typing timeout in milliseconds

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/typing/{self.user_id}"
        data = {"typing": typing, "timeout": timeout} if typing else {"typing": False}
        return await self._request("PUT", endpoint, data=data)

    async def set_presence(
        self, status: str = "online", status_msg: str | None = None
    ) -> dict[str, Any]:
        """
        Set user presence status

        Args:
            status: Presence status ('online', 'unavailable', 'offline')
            status_msg: Optional status message

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/presence/{self.user_id}/status"
        data: dict[str, Any] = {"presence": status}
        if status_msg:
            data["status_msg"] = status_msg
        return await self._request("PUT", endpoint, data=data)

    async def send_read_receipt(self, room_id: str, event_id: str) -> dict[str, Any]:
        """
        Send read receipt for an event

        Args:
            room_id: Room ID
            event_id: Event ID to acknowledge

        Returns:
            Response data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event_id}"
        return await self._request("POST", endpoint, data={})

    async def send_reaction(
        self, room_id: str, event_id: str, emoji: str
    ) -> dict[str, Any]:
        """
        Send a reaction to an event

        According to Matrix spec, reactions use the m.reaction event type
        with m.relates_to containing rel_type: m.annotation

        Args:
            room_id: Room ID
            event_id: Event ID to react to
            emoji: The emoji to react with (e.g., "👍", "❤️")

        Returns:
            Response with event_id of the reaction
        """
        import time

        txn_id = f"{int(time.time() * 1000)}_{id(emoji)}"
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/send/m.reaction/{txn_id}"

        content = {
            "m.relates_to": {
                "rel_type": "m.annotation",
                "event_id": event_id,
                "key": emoji,
            }
        }

        return await self._request("PUT", endpoint, data=content)

    async def get_event(self, room_id: str, event_id: str) -> dict[str, Any]:
        """
        Get a single event from a room

        Args:
            room_id: Room ID
            event_id: Event ID to fetch

        Returns:
            Event data
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/event/{event_id}"

        return await self._request("GET", endpoint)

    async def get_user_room(self, user_id: str) -> str | None:
        """
        Find a direct message room with the specified user

        Args:
            user_id: The user ID to find a DM room for

        Returns:
            The room ID if found, None otherwise
        """
        try:
            # Get direct chat map from account data
            account_data = await self.get_global_account_data("m.direct")
            content = account_data.get("content", {})

            # Look for rooms with this user
            rooms = content.get(user_id, [])
            if rooms and isinstance(rooms, list) and len(rooms) > 0:
                # Return the first room found
                return rooms[0]

            return None
        except Exception as e:
            logger.warning(f"Failed to find DM room for {user_id}: {e}")
            return None

    async def send_room_message(self, room_id: str, message: str) -> dict[str, Any]:
        """
        Helper to send a simple text message to a room

        Args:
            room_id: Room ID
            message: Message text

        Returns:
            Response data
        """
        return await self.send_message(
            room_id, "m.room.message", {"msgtype": "m.text", "body": message}
        )

    async def send_to_device(
        self, event_type: str, messages: dict[str, Any], txn_id: str | None = None
    ) -> dict[str, Any]:
        """
        Send to-device events to specific devices

        Args:
            event_type: The type of event to send
            messages: Dict of user_id -> device_id -> content or Dict of user_id -> content
            txn_id: Transaction ID (auto-generated if not provided)

        Returns:
            Empty dict on success
        """
        import secrets

        if txn_id is None:
            txn_id = secrets.token_hex(16)

        endpoint = f"/_matrix/client/v3/sendToDevice/{event_type}/{txn_id}"

        # 处理不同的消息格式
        if isinstance(messages, dict):
            # 检查是否是 user_id -> device_id -> content 格式
            if messages and isinstance(list(messages.values())[0], dict):
                # 可能是 user_id -> device_id -> content 格式
                first_value = list(messages.values())[0]
                if isinstance(first_value, dict) and not first_value.get("messages"):
                    # 确保格式正确
                    data = {"messages": messages}
                else:
                    # 已经是正确格式
                    data = messages
            else:
                # 假设已经是正确格式
                data = messages
        else:
            data = {"messages": messages}

        # Control verbose logging via environment variable to avoid accidental secret leaks
        verbose_env = os.environ.get("ASTRBOT_VERBOSE_TO_DEVICE", "").lower()
        verbose = verbose_env in ("1", "true", "yes")

        # Helper to produce a short, safe representation of potentially large dicts
        def _short(obj: Any, maxlen: int = RESPONSE_TRUNCATE_LENGTH_400) -> str:
            try:
                s = json.dumps(obj, ensure_ascii=False)
            except Exception:
                s = str(obj)
            if len(s) > maxlen:
                return s[: maxlen - 80] + f"... (truncated, {len(s)} bytes)"
            return s

        # Build request manually so we can capture HTTP status and raw response body
        await self._ensure_session()
        url = f"{self.homeserver}{endpoint}"
        headers = self._get_headers()

        try:
            async with self.session.put(url, json=data, headers=headers) as resp:
                status = resp.status
                # Try to parse JSON, fallback to text
                try:
                    resp_body = await resp.json()
                except Exception:
                    resp_text = await resp.text()
                    resp_body = resp_text

                # Log summary for diagnostics
                try:
                    from astrbot.api import logger as api_logger

                    api_logger.debug(
                        f"send_to_device response for {event_type} txn {txn_id}: status={status} body={_short(resp_body)}"
                    )

                    if verbose:
                        api_logger.debug(
                            f"send_to_device request payload: {_short(data, maxlen=2000)}"
                        )
                        api_logger.debug(
                            f"send_to_device full response: {_short(resp_body, maxlen=2000)}"
                        )
                except Exception:
                    pass

                if status >= HTTP_ERROR_STATUS_400:
                    # Try to extract errcode/message if JSON
                    if isinstance(resp_body, dict):
                        error_code = resp_body.get("errcode", "UNKNOWN")
                        error_msg = resp_body.get("error", "Unknown error")
                    else:
                        error_code = "UNKNOWN"
                        error_msg = str(resp_body)

                    raise Exception(
                        f"Matrix API error: {error_code} - {error_msg} (status: {status})"
                    )

                return resp_body

        except aiohttp.ClientError as e:
            logger.error(
                f"send_to_device network error for {event_type} txn {txn_id}: {e}"
            )
            raise

    async def search(
        self,
        search_term: str,
        keys: list[str] | None = None,
        filter: dict[str, Any] | None = None,
        order_by: str = "recent",
        event_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Search for events matching a search term

        Args:
            search_term: The term to search for
            keys: List of keys to search (default: ["content.body"])
            filter: Filter to apply to the search
            order_by: Order by "recent" or "rank" (default: "recent")
            event_context: Event context to include with results

        Returns:
            Search results
        """
        endpoint = "/_matrix/client/v3/search"
        data = {
            "search_categories": {
                "room_events": {
                    "search_term": search_term,
                    "keys": keys or ["content.body"],
                    "filter": filter or {},
                    "order_by": order_by,
                    "event_context": event_context or {},
                }
            }
        }
        return await self._request("POST", endpoint, data=data)

    # ========== E2EE API ==========

    async def upload_keys(
        self,
        device_keys: dict[str, Any] | None = None,
        one_time_keys: dict[str, Any] | None = None,
        fallback_keys: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Upload device keys, one-time keys, and fallback keys

        Args:
            device_keys: Device identity keys
            one_time_keys: One-time pre-keys
            fallback_keys: Fallback keys

        Returns:
            Response with one_time_key_counts
        """
        endpoint = "/_matrix/client/v3/keys/upload"
        data: dict[str, Any] = {}

        if device_keys:
            data["device_keys"] = device_keys
            # 记录设备密钥信息用于调试
            algorithms = device_keys.get("algorithms", [])
            device_id = device_keys.get("device_id", "unknown")
            logger.info(f"上传设备密钥：device_id={device_id}, algorithms={algorithms}")

        if one_time_keys:
            otk_count = len(one_time_keys)
            logger.debug(f"上传 {otk_count} 个一次性密钥")
            data["one_time_keys"] = one_time_keys
        if fallback_keys:
            logger.debug("上传备用密钥")
            data["fallback_keys"] = fallback_keys

        return await self._request("POST", endpoint, data=data)

    async def query_keys(
        self,
        device_keys: dict[str, list[str]],
        timeout: int = KEY_QUERY_TIMEOUT_MS_10000,
    ) -> dict[str, Any]:
        """
        Query device keys for users

        Args:
            device_keys: Dict of user_id -> list of device_ids (empty list = all devices)
            timeout: Timeout in milliseconds

        Returns:
            Response with device_keys
        """
        endpoint = "/_matrix/client/v3/keys/query"
        data = {"device_keys": device_keys, "timeout": timeout}
        return await self._request("POST", endpoint, data=data)

    async def claim_keys(
        self,
        one_time_keys: dict[str, dict[str, str]],
        timeout: int = 10000,
    ) -> dict[str, Any]:
        """
        Claim one-time keys from other users' devices

        Args:
            one_time_keys: Dict of user_id -> {device_id -> algorithm}
            timeout: Timeout in milliseconds

        Returns:
            Response with claimed one_time_keys
        """
        endpoint = "/_matrix/client/v3/keys/claim"
        data = {"one_time_keys": one_time_keys, "timeout": timeout}
        return await self._request("POST", endpoint, data=data)

    async def get_room_state(self, room_id: str) -> list[dict[str, Any]]:
        """
        Get full state for a room

        Args:
            room_id: Room ID

        Returns:
            List of state events
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state"
        return await self._request("GET", endpoint)

    async def is_room_encrypted(self, room_id: str) -> bool:
        """
        Check if a room has encryption enabled

        Args:
            room_id: Room ID

        Returns:
            True if room is encrypted
        """
        try:
            state = await self.get_room_state(room_id)
            for event in state:
                if event.get("type") == "m.room.encryption":
                    return True
            return False
        except Exception:
            return False

"""SSO flow webhook callback forwarding."""


class MatrixSSOCallbackMixin:
    async def handle_webhook_callback(self, request):
        if not self.callback_server:
            return "SSO flow is not ready, please retry.", 503
        return await self.callback_server.handle_callback(request)

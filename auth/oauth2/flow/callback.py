"""OAuth2 unified webhook callback forwarding."""


class MatrixOAuth2FlowCallbackMixin:
    async def handle_webhook_callback(self, request):
        if not self.callback_server:
            return "OAuth2 flow is not ready, please retry.", 503
        return await self.callback_server.handle_callback(request)

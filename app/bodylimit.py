"""Request body cap: a request whose body exceeds MAX_BODY is refused (413) before the app reads any of it.

Without the cap, Starlette reads a whole body into memory before pydantic's max_length runs, so an unauthenticated client could make
the single worker hold any amount of memory.
"""
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# The largest legitimate body (an id_token of up to 20 000 characters, a plan for 200 ports) stays far below this.
MAX_BODY = 64 * 1024


class BodyLimit:
    """Pure ASGI middleware. Answers 413 when Content-Length announces more than max_bytes, without calling the app; otherwise reads
    the body up to max_bytes (more: 413) and hands it to the app as one message. Later receive() calls go to the server's receive."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        length = _content_length(scope)
        if length is not None and length > self.max_bytes:
            await _too_large(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":         # the client went away: the app learns it as it would without the cap
                break
            body += message.get("body", b"")
            if len(body) > self.max_bytes:
                await _too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                message = {"type": "http.request", "body": bytes(body), "more_body": False}
                break
        first = [message]

        async def replay() -> Message:
            return first.pop() if first else await receive()

        await self.app(scope, replay, send)


def _content_length(scope: Scope) -> int | None:
    """The body size the client announced; None without a Content-Length (a chunked body) or with a malformed one."""
    for name, value in scope["headers"]:
        if name == b"content-length" and value.strip().isdigit():
            return int(value)
    return None


async def _too_large(scope: Scope, receive: Receive, send: Send) -> None:
    await JSONResponse({"detail": "Anfrage zu groß"}, status_code=413)(scope, receive, send)

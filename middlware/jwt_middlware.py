# -*- coding: utf-8 -*-
"""
  Description :   实现Jwt Token认证，并透传User信息
  Author :        Shiyc
  date：          2022/06/22 
"""

import uvicorn
from fastapi import FastAPI, Request
from starlette.responses import StreamingResponse
import typing
from shortuuid import uuid
from websdk.jwt_token import AuthToken, jwt
import anyio

from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import Response

app = FastAPI()


DispatchFunction = typing.Callable[
    [Request, RequestResponseEndpoint], typing.Awaitable[Response]
]

# 定义中间件
class BaseHandler():
    def __init__(
            self, app: ASGIApp, dispatch: typing.Optional[DispatchFunction] = None
    ) -> None:
        self.app = app
        self.dispatch_func = self.dispatch if dispatch is None else dispatch
        self.new_csrf_key = str(uuid())
        self.business_id, self.resource_group = None, None
        self.user_id, self.username, self.nickname, self.email, self.is_super = None, None, None, None, False
        self.is_superuser = self.is_super
        self.token_verify = False
        self.tenant_filter = False
        self.params = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)

        async def call_next(request: Request) -> Response:
            app_exc: typing.Optional[Exception] = None
            send_stream, recv_stream = anyio.create_memory_object_stream()

            async def coro() -> None:
                nonlocal app_exc

                async with send_stream:
                    try:
                        await self.app(scope, request.receive, send_stream.send)
                    except Exception as exc:
                        app_exc = exc

            task_group.start_soon(coro)

            try:
                message = await recv_stream.receive()
            except anyio.EndOfStream:
                if app_exc is not None:
                    raise app_exc
                raise RuntimeError("No response returned.")

            assert message["type"] == "http.response.start"

            async def body_stream() -> typing.AsyncGenerator[bytes, None]:
                async with recv_stream:
                    async for message in recv_stream:
                        assert message["type"] == "http.response.body"
                        yield message.get("body", b"")

                if app_exc is not None:
                    raise app_exc

            response = StreamingResponse(
                status_code=message["status"], content=body_stream()
            )
            response.raw_headers = message["headers"]
            return response

        async with anyio.create_task_group() as task_group:
            request = Request(scope, receive=receive)
            response = await self.dispatch_func(scope, request, call_next)
            await response(scope, receive, send)
            task_group.cancel_scope.cancel()

    # 认证功能模块
    async def login(self, request: Request):
        """
        ### 登陆验证
        :param request:
        :return:
        """

        if request.cookies.get("auth_key"):
            auth_key = request.cookies.get('auth_key')
        else:
            auth_key = request.headers.get('auth-key')

        if not auth_key:
            return 401, "请登录"

        if self.token_verify:
            auth_token = AuthToken()
            user_info = auth_token.decode_auth_token(auth_key)
        else:
            user_info = jwt.decode(auth_key, options={"verify_signature": False}).get('data')

        if not user_info:
            return 401, 'auth failed'

        self.user_id = user_info.get('user_id', None)
        self.username = user_info.get('username', None)
        self.nickname = user_info.get('nickname', None)
        self.email = user_info.get('email', None)
        self.is_super = user_info.get('is_superuser', False)

        if not self.user_id:
            return 401, 'auth failed'

        return 200, "auth success"

    async def dispatch(self, scope: Scope, request: Request, call_next: RequestResponseEndpoint) -> Response:
        status, msg = await self.login(request)
        if status != 200:
            return Response(msg, status)

        self._add_custom_headers(scope, 'is_superuser',  str(self.is_super))

        response = await call_next(request)
        response.set_cookie("user_id", str(self.user_id))
        response.set_cookie("nickname", self.nickname)
        response.set_cookie("username", self.username)
        response.set_cookie("email", str(self.email))
        return response

    # 透传header
    @classmethod
    def _add_custom_headers(cls, scope: Scope, k, v):
        scope["headers"].append((k.encode(), v.encode()))


app.add_middleware(BaseHandler)
@app.post("/test")
def post(req: Request):
    print(req.headers.get('token'))
    print(req.headers.get('is_superuser'))
    return "post"


if __name__ == '__main__':
    uvicorn.run("app", host="localhost", port=8090)


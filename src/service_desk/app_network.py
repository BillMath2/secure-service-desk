"""Fixed-origin routing for Docker Desktop without runtime DNS or proxy discovery."""

import ssl

import httpx

from service_desk.read_bootstrap import destination

PORTS = {"browser": 19481, "agent": 19486, "publisher": 19487}
OUTBOUND = {
    "browser": (19443, 19486, 19487),
    "agent": (15433, 19443, 19482, 19483, 19485),
    "publisher": (15433, 19443),
}


def routed(request: httpx.Request, host_ip: str, ports: tuple[int, ...]) -> httpx.Request:
    expected_scheme = "http" if request.url.port == 19485 else "https"
    if (
        request.url.host != "127.0.0.1"
        or request.url.port not in ports
        or request.url.scheme != expected_scheme
        or request.url.userinfo
    ):
        raise httpx.ConnectError("Destination denied", request=request)
    return httpx.Request(
        request.method,
        request.url.copy_with(host=destination(host_ip)),
        headers=request.headers,
        stream=request.stream,
        extensions={**request.extensions, "sni_hostname": "127.0.0.1"},
    )


class RoutedTransport(httpx.BaseTransport):
    def __init__(self, host_ip: str, ports: tuple[int, ...], trust: ssl.SSLContext) -> None:
        self.host_ip, self.ports = destination(host_ip), ports
        self.inner = httpx.HTTPTransport(verify=trust, trust_env=False, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self.inner.handle_request(routed(request, self.host_ip, self.ports))

    def close(self) -> None:
        self.inner.close()


class RoutedAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, host_ip: str, ports: tuple[int, ...], trust: ssl.SSLContext) -> None:
        self.host_ip, self.ports = destination(host_ip), ports
        self.inner = httpx.AsyncHTTPTransport(verify=trust, trust_env=False, retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.inner.handle_async_request(routed(request, self.host_ip, self.ports))

    async def aclose(self) -> None:
        await self.inner.aclose()

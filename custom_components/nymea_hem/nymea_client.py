"""Async client for the nymea JSON-RPC API."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import Any, Callable

_LOGGER = logging.getLogger(__name__)

BACKOFF_DELAYS = (60.0, 120.0, 240.0, 300.0)


class NymeaError(Exception):
    """Base exception raised by the nymea client."""


class NymeaConnectionError(NymeaError):
    """The transport is unavailable or a reconnect is cooling down."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class NymeaRequestTimeout(NymeaError):
    """The server did not answer a request within the expected time."""


class NymeaAuthenticationError(NymeaError):
    """The server definitively rejected authentication."""


class NymeaRpcError(NymeaError):
    """Nymea returned an error for an otherwise completed RPC request."""


class NymeaClient:
    """Client for Nymea HEM JSON-RPC communication."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        ssl_enabled: bool = True,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._ssl_enabled = ssl_enabled
        self._token: str | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connection_timeout = 10
        self._read_timeout = 15
        self._request_id = 0
        self._receive_buffer = ""
        # StreamReader only permits one active reader. Reconnect, authentication,
        # polling and actions therefore share this lock for their entire exchange.
        self._request_lock = asyncio.Lock()
        self._server_info: dict[str, Any] = {}
        self._session_ready = False
        self._authentication_blocked = False
        self._consecutive_read_timeouts = 0
        self._reconnect_failures = 0
        self._next_reconnect_at = 0.0
        self._monotonic = monotonic

    @property
    def authentication_blocked(self) -> bool:
        """Return whether credentials were definitively rejected."""
        return self._authentication_blocked

    @property
    def reconnect_failures(self) -> int:
        """Return the number of consecutive recovery failures."""
        return self._reconnect_failures

    @property
    def next_reconnect_at(self) -> float:
        """Return the monotonic timestamp of the next permitted reconnect."""
        return self._next_reconnect_at

    @property
    def consecutive_read_timeouts(self) -> int:
        """Return consecutive response timeouts for the current session."""
        return self._consecutive_read_timeouts

    def is_connected(self) -> bool:
        """Return whether the socket is open.

        This only describes transport state. A usable session additionally needs
        ``_session_ready`` and must not be in an authentication-blocked state.
        """
        return bool(
            self._reader
            and self._writer
            and not self._writer.is_closing()
        )

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _safe_error_detail(self, value: Any) -> str:
        """Return a server error string with locally known secrets removed."""
        detail = str(value) if value else "unknown RPC error"
        for secret in (self._password, self._token):
            if secret:
                detail = detail.replace(secret, "[redacted]")
        return detail

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create a TLS context suitable for a self-signed local appliance."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _raise_if_reconnect_not_allowed(self) -> None:
        if self._authentication_blocked:
            raise NymeaAuthenticationError(
                "Nymea rejected the configured credentials; "
                "reauthentication is required"
            )
        remaining = self._next_reconnect_at - self._monotonic()
        if remaining > 0:
            raise NymeaConnectionError(
                f"Nymea reconnect is cooling down for {remaining:.1f} seconds",
                retry_after=remaining,
            )

    def _record_recovery_failure(self) -> None:
        """Advance the reconnect circuit breaker after an actual I/O attempt."""
        self._reconnect_failures += 1
        delay = BACKOFF_DELAYS[
            min(self._reconnect_failures - 1, len(BACKOFF_DELAYS) - 1)
        ]
        self._next_reconnect_at = self._monotonic() + delay
        _LOGGER.debug(
            "Nymea connection recovery delayed for %.0f seconds after failure %d",
            delay,
            self._reconnect_failures,
        )

    def _reset_recovery_state(self) -> None:
        self._consecutive_read_timeouts = 0
        self._reconnect_failures = 0
        self._next_reconnect_at = 0.0

    async def _connect_locked(self) -> None:
        if self.is_connected():
            return
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._host,
                    self._port,
                    ssl=self._create_ssl_context() if self._ssl_enabled else None,
                ),
                timeout=self._connection_timeout,
            )
        except (asyncio.TimeoutError, OSError) as err:
            raise NymeaConnectionError(
                f"Could not connect to {self._host}:{self._port}"
            ) from err
        _LOGGER.info("Successfully connected to %s:%d", self._host, self._port)

    async def _read_response_locked(
        self, request_id: int, timeout: float | None = None
    ) -> dict[str, Any]:
        """Read JSON objects until the response for ``request_id`` arrives."""
        if self._reader is None:
            raise NymeaConnectionError("Nymea connection has no reader")
        decoder = json.JSONDecoder()
        read_timeout = self._read_timeout if timeout is None else timeout
        while True:
            while self._receive_buffer.lstrip():
                stripped = self._receive_buffer.lstrip()
                try:
                    message, end = decoder.raw_decode(stripped)
                except json.JSONDecodeError:
                    break
                self._receive_buffer = stripped[end:]
                if not isinstance(message, dict):
                    continue
                if message.get("id") == request_id:
                    return message
                _LOGGER.debug(
                    "Ignoring unsolicited or late nymea message id=%s while "
                    "waiting for id=%s",
                    message.get("id"),
                    request_id,
                )

            try:
                chunk = await asyncio.wait_for(
                    self._reader.read(4096), timeout=read_timeout
                )
            except asyncio.TimeoutError as err:
                raise NymeaRequestTimeout(
                    f"No response for request {request_id} within "
                    f"{read_timeout} seconds"
                ) from err
            except (ConnectionError, OSError) as err:
                raise NymeaConnectionError(
                    "Nymea connection failed while reading a response"
                ) from err
            if not chunk:
                raise NymeaConnectionError("Connection closed by remote host")
            try:
                self._receive_buffer += chunk.decode()
            except UnicodeDecodeError as err:
                raise NymeaConnectionError(
                    "Nymea returned an invalid response encoding"
                ) from err

    async def _send_locked(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        include_token: bool = True,
        response_timeout: float | None = None,
    ) -> dict[str, Any]:
        if self._writer is None:
            raise NymeaConnectionError("Nymea connection has no writer")
        request_id = self._next_request_id()
        request: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        if include_token and self._token:
            request["token"] = self._token

        # Do not log params: authentication params contain the password, and the
        # serialized request can contain a token.
        _LOGGER.debug("Sending nymea request id=%s method=%s", request_id, method)
        try:
            self._writer.write((json.dumps(request) + "\n").encode())
            await self._writer.drain()
        except (ConnectionError, OSError) as err:
            raise NymeaConnectionError(
                f"Nymea connection failed while sending {method}"
            ) from err

        response = await self._read_response_locked(request_id, response_timeout)
        status = response.get("status")
        if status == "unauthorized":
            raise NymeaAuthenticationError("Nymea rejected authentication")
        if status != "success":
            detail = self._safe_error_detail(response.get("error"))
            raise NymeaRpcError(f"{method} failed: {detail}")
        return response

    async def _authenticate_locked(self) -> None:
        """Build a fresh session; callers handle failure state and cooldown."""
        # A complete login must never reuse a socket, receive buffer or token.
        await self._close_locked()
        await self._connect_locked()
        hello = await self._send_locked("JSONRPC.Hello", include_token=False)
        hello_params = hello.get("params", {})
        self._server_info = {
            "authentication_required": hello_params.get("authenticationRequired"),
            "experiences": hello_params.get("experiences", []),
            "initial_setup_required": hello_params.get("initialSetupRequired"),
            "language": hello_params.get("language"),
            "locale": hello_params.get("locale"),
            "name": hello_params.get("name"),
            "protocol_version": hello_params.get("protocol version"),
            "server": hello_params.get("server"),
            "uuid": hello_params.get("uuid"),
            "version": hello_params.get("version"),
        }

        if hello_params.get("authenticationRequired", True):
            auth = await self._send_locked(
                "JSONRPC.Authenticate",
                {
                    "username": self._username,
                    "password": self._password,
                    "deviceName": "HomeAssistant",
                },
                include_token=False,
            )
            auth_params = auth.get("params", {})
            if not auth_params.get("success", False) or not auth_params.get("token"):
                raise NymeaAuthenticationError(
                    "Nymea rejected the configured credentials"
                )
            self._token = auth_params["token"]

        self._session_ready = True
        self._consecutive_read_timeouts = 0
        _LOGGER.info(
            "Authenticated with %s (version %s)",
            self._server_info.get("name"),
            self._server_info.get("version"),
        )

    async def _establish_session_locked(self) -> None:
        """Authenticate once, applying the shared circuit breaker on failure."""
        self._raise_if_reconnect_not_allowed()
        try:
            await self._authenticate_locked()
        except NymeaAuthenticationError:
            self._authentication_blocked = True
            await self._close_locked()
            raise
        except (NymeaConnectionError, NymeaRequestTimeout, NymeaRpcError):
            await self._close_locked()
            self._record_recovery_failure()
            raise

    async def authenticate(self) -> None:
        """Create a fresh authenticated session."""
        async with self._request_lock:
            await self._establish_session_locked()

    async def _rpc_call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        response_timeout: float | None = None,
    ) -> dict[str, Any]:
        async with self._request_lock:
            if self._authentication_blocked:
                raise NymeaAuthenticationError(
                    "Nymea reauthentication is required"
                )
            if not self.is_connected() or not self._session_ready:
                await self._establish_session_locked()

            try:
                response = await self._send_locked(
                    method, params, response_timeout=response_timeout
                )
            except NymeaRequestTimeout:
                self._consecutive_read_timeouts += 1
                if self._consecutive_read_timeouts >= 2:
                    await self._close_locked()
                    self._record_recovery_failure()
                # The first timeout deliberately keeps the socket. A late reply
                # is ignored by request id during the next serialized exchange.
                raise
            except NymeaAuthenticationError:
                self._authentication_blocked = True
                await self._close_locked()
                raise
            except NymeaConnectionError:
                await self._close_locked()
                self._record_recovery_failure()
                raise

            self._consecutive_read_timeouts = 0
            if method == "Integrations.GetThings":
                # Only a completed state poll proves end-to-end recovery.
                self._reset_recovery_state()
            return response

    async def get_things(self) -> list[dict[str, Any]]:
        """Retrieve all configured things."""
        response = await self._rpc_call("Integrations.GetThings")
        things = response.get("params", {}).get("things", [])
        _LOGGER.debug("Retrieved %d devices from Nymea", len(things))
        return things

    async def get_thing_class_details(
        self, thing_class_id: str
    ) -> list[dict[str, Any]]:
        """Retrieve complete metadata for one thing class."""
        response = await self._rpc_call(
            "Integrations.GetThingClasses", {"thingClassIds": [thing_class_id]}
        )
        return response.get("params", {}).get("thingClasses", [])

    async def execute_action(
        self,
        thing_id: str,
        action_type_id: str,
        action_params: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Execute an action and return whether nymea confirmed completion.

        Actions use a shorter response timeout. An unconfirmed action returns
        ``False`` to preserve read-back handling, while the shared two-timeout
        health policy still discards a repeatedly unresponsive session.
        """
        params: dict[str, Any] = {
            "thingId": thing_id,
            "actionTypeId": action_type_id,
        }
        if action_params:
            params["params"] = action_params
        _LOGGER.info(
            "Executing nymea action thing=%s actionType=%s paramTypes=%s",
            thing_id,
            action_type_id,
            [item.get("paramTypeId") for item in action_params or []],
        )
        try:
            response = await self._rpc_call(
                "Integrations.ExecuteAction", params, response_timeout=5
            )
        except NymeaRequestTimeout:
            _LOGGER.info(
                "Nymea action %s was not confirmed in time; its state will be "
                "read back",
                action_type_id,
            )
            return False
        result = response.get("params", {})
        thing_error = result.get("thingError")
        if thing_error == "ThingErrorTimeout":
            _LOGGER.info(
                "Nymea action %s returned ThingErrorTimeout; the command may "
                "still have been applied and its state will be refreshed",
                action_type_id,
            )
            return False
        if thing_error not in (None, "ThingErrorNoError", 0):
            message = result.get("displayMessage") or thing_error
            raise NymeaRpcError(
                f"Action failed: {self._safe_error_detail(message)}"
            )
        _LOGGER.info("Nymea action %s completed successfully", action_type_id)
        return True

    async def _close_locked(self) -> None:
        writer = self._writer
        self._reader = None
        self._writer = None
        self._token = None
        self._session_ready = False
        self._receive_buffer = ""
        self._consecutive_read_timeouts = 0
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError, ssl.SSLError):
                pass

    async def close_connection(self) -> None:
        """Close the connection safely and discard the session token."""
        async with self._request_lock:
            await self._close_locked()

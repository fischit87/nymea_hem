"""Config, reauthentication and reconfiguration flows for Nymea HEM."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME

from .const import (
    CONF_POLL_INTERVAL,
    CONF_SSL,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_PORT,
    DEFAULT_SSL,
    DOMAIN,
)
from .nymea_client import (
    NymeaAuthenticationError,
    NymeaClient,
    NymeaConnectionError,
    NymeaRequestTimeout,
    NymeaRpcError,
)

_LOGGER = logging.getLogger(__name__)


class NymeaHEMConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Nymea HEM."""

    VERSION = 1

    async def _async_validate(self, data: dict[str, Any]) -> None:
        """Validate one explicitly submitted connection configuration."""
        client = NymeaClient(
            host=data[CONF_HOST],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            ssl_enabled=data.get(CONF_SSL, DEFAULT_SSL),
        )
        try:
            await client.authenticate()
        finally:
            # Config-flow validation never owns a long-lived session or token.
            await client.close_connection()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            data = self._normalized_data(user_input)
            try:
                await self._async_validate(data)
            except NymeaAuthenticationError:
                errors["base"] = "invalid_auth"
            except (NymeaConnectionError, NymeaRequestTimeout):
                errors["base"] = "cannot_connect"
            except NymeaRpcError:
                errors["base"] = "unknown"
            except Exception:
                _LOGGER.exception("Unexpected error validating Nymea configuration")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=f"Nymea HEM - {data[CONF_HOST]}", data=data
                )

        return self._show_config_form(errors, user_input)

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> config_entries.ConfigFlowResult:
        """Start reauth without automatically retrying stored credentials."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Validate and store replacement credentials."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {
                **entry.data,
                CONF_USERNAME: user_input[CONF_USERNAME],
                CONF_PASSWORD: user_input[CONF_PASSWORD],
            }
            try:
                await self._async_validate(data)
            except NymeaAuthenticationError:
                errors["base"] = "invalid_auth"
            except (NymeaConnectionError, NymeaRequestTimeout):
                errors["base"] = "cannot_connect"
            except NymeaRpcError:
                errors["base"] = "unknown"
            except Exception:
                _LOGGER.exception("Unexpected error during Nymea reauthentication")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_USERNAME: data[CONF_USERNAME],
                        CONF_PASSWORD: data[CONF_PASSWORD],
                    },
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=(user_input or entry.data).get(CONF_USERNAME, ""),
                    ): str,
                    # Deliberately do not put the stored password back into the
                    # form or logs; the user must submit the replacement value.
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Update endpoint and polling settings after explicit validation."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {
                **entry.data,
                CONF_HOST: user_input[CONF_HOST],
                CONF_PORT: user_input.get(CONF_PORT, DEFAULT_PORT),
                CONF_SSL: user_input.get(CONF_SSL, DEFAULT_SSL),
                CONF_POLL_INTERVAL: user_input.get(
                    CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL
                ),
            }
            try:
                await self._async_validate(data)
            except NymeaAuthenticationError:
                errors["base"] = "invalid_auth"
            except (NymeaConnectionError, NymeaRequestTimeout):
                errors["base"] = "cannot_connect"
            except NymeaRpcError:
                errors["base"] = "unknown"
            except Exception:
                _LOGGER.exception("Unexpected error reconfiguring Nymea")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_HOST: data[CONF_HOST],
                        CONF_PORT: data[CONF_PORT],
                        CONF_SSL: data[CONF_SSL],
                        CONF_POLL_INTERVAL: data[CONF_POLL_INTERVAL],
                    },
                )

        defaults = user_input or entry.data
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self._connection_schema(defaults, credentials=False),
            errors=errors,
        )

    @staticmethod
    def _normalized_data(user_input: dict[str, Any]) -> dict[str, Any]:
        return {
            CONF_HOST: user_input[CONF_HOST],
            CONF_PORT: user_input.get(CONF_PORT, DEFAULT_PORT),
            CONF_USERNAME: user_input[CONF_USERNAME],
            CONF_PASSWORD: user_input[CONF_PASSWORD],
            CONF_SSL: user_input.get(CONF_SSL, DEFAULT_SSL),
            CONF_POLL_INTERVAL: user_input.get(
                CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL
            ),
        }

    @staticmethod
    def _connection_schema(
        defaults: dict[str, Any] | None = None, *, credentials: bool = True
    ) -> vol.Schema:
        values = defaults or {}
        fields: dict[Any, Any] = {
            vol.Required(CONF_HOST, default=values.get(CONF_HOST, "")): str,
            vol.Required(
                CONF_PORT, default=values.get(CONF_PORT, DEFAULT_PORT)
            ): int,
        }
        if credentials:
            fields.update(
                {
                    vol.Required(
                        CONF_USERNAME, default=values.get(CONF_USERNAME, "")
                    ): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            )
        fields.update(
            {
                vol.Optional(
                    CONF_SSL, default=values.get(CONF_SSL, DEFAULT_SSL)
                ): bool,
                vol.Optional(
                    CONF_POLL_INTERVAL,
                    default=values.get(
                        CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL
                    ),
                ): int,
            }
        )
        return vol.Schema(fields)

    def _show_config_form(
        self,
        errors: dict[str, str] | None = None,
        user_input: dict[str, Any] | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Show the initial configuration form."""
        return self.async_show_form(
            step_id="user",
            data_schema=self._connection_schema(user_input),
            errors=errors or {},
        )

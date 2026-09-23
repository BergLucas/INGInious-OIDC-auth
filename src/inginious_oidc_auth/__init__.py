from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import flask
import requests
from flask import Response, send_from_directory
from inginious.frontend.pages.utils import INGIniousPage
from inginious.frontend.user_manager import AuthMethod
from pydantic import BaseModel
from requests_oauthlib import OAuth2Session

if TYPE_CHECKING:
    from inginious.client.client import Client
    from inginious.frontend.plugins import PluginManager


class OidcClient(BaseModel):
    """Client configuration for the OIDC authentication plugin."""

    id: str
    secret: str


class OidcEndpoints(BaseModel):
    """Endpoints for the OIDC provider."""

    authorization_url: str
    token_url: str
    userinfo_url: str


class OidcProfile(BaseModel):
    """OIDC profile configuration."""

    id_key: str = "sub"
    name_key: str = "name"
    email_key: str = "email"


class OidcPluginConfig(BaseModel):
    """Configuration for the OIDC authentication plugin."""

    id: str = "oidc"
    name: str = "OpenID Connect (OIDC)"
    client: OidcClient
    oidc_config_url: str
    icon_url: str
    static_path: str = ""
    profile: OidcProfile = OidcProfile()
    scope: list[str] = []
    timeout: int = 5
    debug: bool = False


class OidcAuthMethod(AuthMethod):
    """OIDC authentication method."""

    @property
    def _redirect_uri(self) -> str:
        return flask.request.url_root + "auth/callback/" + self._id

    def get_auth_link(self, auth_storage: dict[str, Any]) -> str:
        microsoft = OAuth2Session(
            self._client.id,
            scope=self._scope,
            redirect_uri=self._redirect_uri,
        )

        authorization_url, state = microsoft.authorization_url(
            self._endpoints.authorization_url,
        )

        auth_storage["oauth_state"] = state

        return authorization_url

    def callback(
        self, auth_storage: dict[str, Any]
    ) -> tuple[str, str, str, dict] | None:
        microsoft = OAuth2Session(
            self._client.id,
            state=auth_storage["oauth_state"],
            scope=self._scope,
            redirect_uri=self._redirect_uri,
        )

        try:
            microsoft.fetch_token(
                self._endpoints.token_url,
                client_secret=self._client.secret,
                authorization_response=flask.request.url,
                timeout=self._timeout,
            )

            response = microsoft.get(
                self._endpoints.userinfo_url,
                timeout=self._timeout,
            )

            profile = json.loads(response.content.decode("utf-8"))
        except Exception:
            return None

        if (email := profile.get(self._profile.email_key)) is None:
            return None

        profile_id = str(profile[self._profile.id_key])

        return profile_id, profile.get(self._profile.name_key, profile_id), email, {}

    def __init__(  # noqa: PLR0913, PLR0917
        self,
        id: str,
        name: str,
        client: OidcClient,
        endpoints: OidcEndpoints,
        scope: list[str],
        icon_url: str,
        profile: OidcProfile,
        timeout: int,
    ):
        self._id = id
        self._name = name
        self._client = client
        self._endpoints = endpoints
        self._scope = scope
        self._icon_url = icon_url
        self._profile = profile
        self._timeout = timeout

    def get_id(self) -> str:
        return self._id

    def get_name(self) -> str:
        return self._name

    def get_imlink(self) -> str:
        return f'<img src="{self._icon_url}">'


def init(
    plugin_manager: PluginManager, client: Client, raw_plugin_config: dict[str, Any]
):
    plugin_config = OidcPluginConfig(**raw_plugin_config)

    if plugin_config.debug:
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    oidc_config: dict[str, Any] = requests.get(
        plugin_config.oidc_config_url, timeout=plugin_config.timeout
    ).json()

    authorization_endpoint: str = oidc_config["authorization_endpoint"]
    token_endpoint: str = oidc_config["token_endpoint"]
    userinfo_endpoint: str = oidc_config["userinfo_endpoint"]

    if plugin_config.static_path:
        class OidcAuthStatic(INGIniousPage):
            """Serve static files for the OIDC authentication plugin."""

            def GET(self, path: str) -> Response:  # noqa: N802
                """Serve static files for the OIDC authentication plugin.

                Args:
                    path: The path to the static file.

                Returns:
                    The static file.
                """
                return send_from_directory(plugin_config.static_path, path)

        plugin_manager.add_page(
            "/plugins/oidc-auth/static/<path:path>",
            OidcAuthStatic.as_view("oidc_auth_static"),
        )

    plugin_manager.register_auth_method(
        OidcAuthMethod(
            plugin_config.id,
            plugin_config.name,
            plugin_config.client,
            OidcEndpoints(
                authorization_url=authorization_endpoint,
                token_url=token_endpoint,
                userinfo_url=userinfo_endpoint,
            ),
            plugin_config.scope,
            plugin_config.icon_url,
            plugin_config.profile,
            plugin_config.timeout,
        )
    )

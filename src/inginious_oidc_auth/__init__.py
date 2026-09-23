from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

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
    """A OIDC client."""

    id: str
    secret: str


class OidcEndpoints(BaseModel):
    """Endpoints for the OIDC provider."""

    authorization_url: str
    token_url: str
    userinfo_url: str


class OidcProfile(BaseModel):
    """A OIDC profile."""

    id_key: str = "sub"
    name_key: str = "name"
    email_key: str = "email"


class OidcProvider(BaseModel):
    """A OIDC provider."""

    name: str
    client: OidcClient
    issuer_url: str | OidcEndpoints
    icon_url: str
    profile: OidcProfile = OidcProfile()
    scope: list[str] = []


class OidcPluginConfig(BaseModel):
    """Configuration for the OIDC authentication plugin."""

    debug: bool = False
    static_path: str = ""
    timeout: int = 5
    providers: dict[str, OidcProvider] = {}


class OidcAuthMethod(AuthMethod):
    """OIDC authentication method."""

    @property
    def _redirect_uri(self) -> str:
        return flask.request.url_root + "auth/callback/" + self._id

    def get_auth_link(self, auth_storage: dict[str, Any]) -> str:  # noqa: D102
        session = OAuth2Session(
            self._client.id,
            scope=self._scope,
            redirect_uri=self._redirect_uri,
        )

        authorization_url, state = session.authorization_url(
            self._endpoints.authorization_url,
        )

        auth_storage["oauth_state"] = state

        return authorization_url

    def callback(  # noqa: D102
        self, auth_storage: dict[str, Any]
    ) -> tuple[str, str, str, dict] | None:
        session = OAuth2Session(
            self._client.id,
            state=auth_storage["oauth_state"],
            scope=self._scope,
            redirect_uri=self._redirect_uri,
        )

        try:
            session.fetch_token(
                self._endpoints.token_url,
                client_secret=self._client.secret,
                authorization_response=flask.request.url,
                timeout=self._timeout,
            )

            response = session.get(
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

    def __init__(  # noqa: PLR0913, PLR0917, D107
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

    def get_id(self) -> str:  # noqa: D102
        return self._id

    def get_name(self) -> str:  # noqa: D102
        return self._name

    def get_imlink(self) -> str:  # noqa: D102
        return f'<img src="{self._icon_url}">'


def init(
    plugin_manager: PluginManager, client: Client, raw_plugin_config: dict[str, Any]
):
    """Initialises the OIDC authentication plugin.

    Args:
        plugin_manager: The plugin manager instance.
        client: The client instance.
        raw_plugin_config: The plugin configuration dictionary.
    """
    plugin_config = OidcPluginConfig(**raw_plugin_config)

    if plugin_config.debug:
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

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

    for provider_id, provider in plugin_config.providers.items():
        if isinstance(provider.issuer_url, OidcEndpoints):
            oidc_endpoints = provider.issuer_url
        else:
            discovery_url = urljoin(
                provider.issuer_url,
                ".well-known/openid-configuration",
            )
            openid_config = requests.get(
                discovery_url,
                timeout=plugin_config.timeout,
            ).json()
            oidc_endpoints = OidcEndpoints(
                authorization_url=openid_config["authorization_endpoint"],
                token_url=openid_config["token_endpoint"],
                userinfo_url=openid_config["userinfo_endpoint"],
            )

        plugin_manager.register_auth_method(
            OidcAuthMethod(
                provider_id,
                provider.name,
                provider.client,
                oidc_endpoints,
                provider.scope,
                provider.icon_url,
                provider.profile,
                plugin_config.timeout,
            )
        )

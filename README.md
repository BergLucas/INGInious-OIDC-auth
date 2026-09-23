# INGInious-OIDC-auth

INGInious-OIDC-auth is a plugin that adds OpenID Connect (OIDC) authentication support to INGIinious.

- **Downloads page:** https://github.com/BergLucas/INGInious-OIDC-auth/releases

## Requirements

The application requires:

- [Python](https://www.python.org/) ~= 3.9
- [pip](https://pip.pypa.io/en/stable/)

## Download & Installation

There are two ways to download and install the application:

### Using Git

You can install the application using Git by running the following command:

```bash
pip install git+https://github.com/BergLucas/INGInious-OIDC-auth.git
```

### Using the GitHub releases

You can download the application on the [downloads page](https://github.com/BergLucas/INGInious-OIDC-auth/releases). Then, you can install the application by running the following command:

```bash
pip install inginious_regex_short_answer_problem-X.X.X-py3-none-any.whl
```

(Note: The X.X.X must be replaced by the version that you want to install.)

## Example configuration

Here is an example configuration for the plugin to support Microsoft 365 authentication:

```yaml
- plugin_module: inginious_oidc_auth
  providers:
    microsoft365:
      name: "Microsoft 365"
      client:
        id: "<YOUR_CLIENT_ID>"
        secret: "<YOUR_CLIENT_SECRET>"
      oidc_config_url: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
      icon_url: "https://learn.microsoft.com/en-us/entra/identity-platform/media/howto-add-branding-in-apps/ms-symbollockup_signin_light.svg"
      scope: ["openid", "profile"]
```

## License

All code is licensed for others under a MIT license (see [LICENSE](https://github.com/BergLucas/INGInious-OIDC-auth/blob/main/LICENSE)).

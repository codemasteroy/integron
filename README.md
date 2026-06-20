# Integron

## Prerequisite

- Go 1.25.0 or higher

## Trying out

```
go run main.go
```

## Configuration

### Command-line flags

| Flag    | Default             | Description                  |
| ------- | ------------------- | ---------------------------- |
| `-spec` | `docs/openapi.yaml` | Path to the OpenAPI spec.    |

### Environment variables

The server boots without any environment variables set. Auth-related variables
are required only when the corresponding security scheme is referenced by an
operation's `security` block in the OpenAPI spec.

| Variable                  | Required                          | Default          | Description                                                                                                   |
| ------------------------- | --------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `LOG_LEVEL`               | No                                | `panic`          | Log verbosity: `debug`, `info`, `warn`, `error`, `fatal`, or `panic`. An unset/unknown value logs panics only. |
| `INTEGRON_BASIC_USERNAME` | When using `basicAuth`            | empty            | Username accepted for HTTP Basic auth.                                                                         |
| `INTEGRON_BASIC_PASSWORD` | When using `basicAuth`            | empty            | Password accepted for HTTP Basic auth.                                                                         |
| `INTEGRON_BEARER_TOKEN`   | When using `bearerAuth`           | empty            | Static token accepted for HTTP Bearer auth.                                                                    |
| `INTEGRON_OIDC_ISSUER`    | No (for `oidcAuth`)               | derived          | OIDC issuer URL. When unset, the issuer is derived from the scheme's `openIdConnectUrl` in the spec.           |
| `INTEGRON_OIDC_AUDIENCE`  | No (for `oidcAuth`)               | empty            | Expected token audience (`aud`). When empty, the audience check is skipped (signature, `exp`, and `iss` are still verified). |

> **Note:** The static `basicAuth`/`bearerAuth` verifiers compare against the
> configured values as-is. If you leave `INTEGRON_BEARER_TOKEN` unset, an empty
> token would be accepted — set a real value (or use `oidcAuth`) for any scheme
> you actually rely on.

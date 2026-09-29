# Componenta HTTP CORS Middleware

PSR-15 CORS middleware for PHP 8.4+. The package implements the server side of the Fetch CORS protocol with a conservative, default-deny policy.

CORS controls whether browser JavaScript may read a cross-origin response. It is **not** an authentication, authorization, or CSRF mechanism. A disallowed simple cross-origin request can still reach the application; the browser only prevents the calling script from reading the response.

## Installation

```bash
composer require componenta/http-cors-middleware
```

The package requires a PSR-17 `ResponseFactoryInterface`.

## Secure configuration

No origin is allowed by default:

```php
use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\CorsMiddleware;

$config = new CorsConfiguration(
    allowedOrigins: ['https://app.example.com'],
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-Request-Id'],
    allowCredentials: true,
    maxAge: 600,
);

$middleware = new CorsMiddleware($config, $responseFactory);
```

Opaque `null` origins are rejected in every mode. Sandboxed documents and other opaque-origin contexts can deliberately produce `Origin: null`, so it is not a trustworthy allowlist identity.

When `allowCredentials` is enabled, every allowed origin must be an explicit HTTP(S) origin. The configuration additionally rejects `*`.

This prevents an arbitrary origin from being reflected together with `Access-Control-Allow-Credentials: true`.

Without credentials, `*` is supported:

```php
new CorsConfiguration(
    allowedOrigins: ['*'],
    allowedMethods: ['GET'],
);
```

The wildcard intentionally does not match the opaque `null` origin, and `null` cannot be configured as an allowed origin.

## Origin parsing

Origins are parsed as serialized origins, not generic URLs, and allowlists are exact. An origin must be exactly:

```text
http://host[:port]
https://host[:port]
```

User information, paths, query strings, fragments, invalid hosts, and port zero are rejected. Scheme and host are normalized to lowercase and default ports 80/443 are removed.

Allowed private origins must be exact HTTP(S) origins. Subdomain wildcard patterns such as `https://*.example.com` are rejected in every mode because a single dangling or less-trusted sibling hostname can turn a wildcard policy into unintended cross-origin access. Use explicit origins instead. The only wildcard is the full `*` policy for deliberately public, non-credentialed resources.

> **v3.0 upgrade note:** subdomain wildcard patterns were removed. Replace every `https://*.example.com`-style entry with an explicit list of trusted origins when upgrading from v2.

## Preflight

A CORS preflight is intercepted only when the request contains:

- method `OPTIONS`;
- `Origin`;
- `Access-Control-Request-Method`.

The requested method and header names are validated using HTTP token/field-name grammar. HTTP method matching is case-sensitive as required by RFC 9110; custom method spelling is preserved exactly. Malformed or disallowed requests receive 403 and are not forwarded to the application.

Successful preflights receive 204 plus the configured CORS response fields.

`Authorization` is a CORS non-wildcard request header. Therefore, when `allowedHeaders: ['*']` is used and the preflight requests `Authorization`, the middleware explicitly returns the requested header names instead of `Access-Control-Allow-Headers: *`.

## Credentials

Credentialed CORS is deliberately explicit:

```php
new CorsConfiguration(
    allowedOrigins: ['https://app.example.com'],
    allowedMethods: ['POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['X-Request-Id'],
    allowCredentials: true,
);
```

`Access-Control-Expose-Headers: *` is rejected with credentials because the Fetch Standard treats `*` literally in credential mode.

Wildcard methods or request headers may still be configured intentionally. In credential mode they are reflected as the concrete requested method/header names rather than emitted as `*`.

## Legacy Private Network Access compatibility

`allowPrivateNetwork` implements the legacy Private Network Access (PNA) preflight headers for compatibility with clients that still send them:

```php
new CorsConfiguration(
    allowedOrigins: ['https://admin.example.com'],
    allowedMethods: ['POST'],
    allowPrivateNetwork: true,
);
```

Legacy PNA requires an explicit non-opaque origin. If a preflight sends `Access-Control-Request-Private-Network: true` while this compatibility mode is disabled, the middleware rejects it. Responses vary on `Access-Control-Request-Private-Network` whenever that request field can affect the result.

Current Local Network Access (LNA) replaces the old PNA preflight design with a browser permission model. Therefore `allowPrivateNetwork` is **not** a current LNA authorization or security boundary; application authorization and CSRF defenses remain mandatory.

## Response ownership

The middleware owns all CORS response fields. After the application handler returns, existing downstream values such as:

- `Access-Control-Allow-Origin`;
- `Access-Control-Allow-Credentials`;
- `Access-Control-Allow-Methods`;
- `Access-Control-Allow-Headers`;
- `Access-Control-Expose-Headers`;
- `Access-Control-Max-Age`;
- `Access-Control-Allow-Private-Network`

are removed and rebuilt only from the configured policy.

This prevents a handler from bypassing the central CORS policy by adding a permissive header.

## Cache correctness

Responses include `Vary: Origin`. Preflight responses also vary on:

- `Access-Control-Request-Method`;
- `Access-Control-Request-Headers`;
- `Access-Control-Request-Private-Network` when relevant.

An existing `Vary: *` remains `Vary: *`; field names are not appended to the wildcard.

## Verification

The repository quality workflow verifies:

- PHP 8.4 and 8.5;
- lowest and highest supported dependency sets;
- `composer validate --strict`;
- `composer audit`;
- PHPStan level max over `src` and `tests`;
- PHPUnit security/protocol regression tests.

## Standards

The normative CORS processing model is defined by the WHATWG Fetch Living Standard. HTTP field syntax and cache semantics follow RFC 9110. Origin semantics are based on RFC 6454.

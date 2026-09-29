# Changelog

## v2.0.1

Standards-correctness patch release.

### Fixed
- HTTP and CORS method matching is now case-sensitive as required by RFC 9110.
- Configured custom methods preserve their exact spelling.
- Lowercase `options` is no longer treated as the standard `OPTIONS` CORS preflight method.
- Credentialed wildcard method responses preserve the exact requested method token.

### Verification
- PHP 8.4 and 8.5, lowest and highest dependency sets.
- Composer strict validation and security audit.
- PHPStan level max over source and tests.
- Strict PHPUnit configuration.
- Infection mutation coverage 100%, covered-code MSI 86%.

## v2.0.0

Breaking security-focused release.

### Security
- CORS is default-deny: an empty configuration no longer allows arbitrary origins.
- Credentialed CORS requires exact non-opaque HTTP(S) origins; `*`, `null`, and subdomain wildcards are rejected.
- Downstream CORS response headers are stripped and rebuilt from the central policy.
- Serialized origins are parsed strictly; URL paths, query strings, fragments, userinfo, malformed hosts, and port 0 are rejected.
- Preflight method/header names are validated as HTTP tokens.
- `Authorization` is handled explicitly when request-header wildcard configuration is used.
- Private Network Access requires explicit origins and participates in `Vary`.
- Rejected preflights are returned with `Cache-Control: no-store`.

### Compatibility
- Requires `psr/http-factory ^1.1`.
- Test implementation floor is `nyholm/psr7 ^1.8.2` for PHP 8.4 compatibility.
- Applications upgrading from v1 must explicitly configure `allowedOrigins`.

### Verification
- PHP 8.4 and 8.5, lowest and highest dependency sets.
- Composer strict validation and security audit.
- PHPStan level max over source and tests.
- Strict PHPUnit configuration.
- Infection mutation coverage 100%, covered-code MSI 85%.

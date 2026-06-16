<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors;

/**
 * Immutable CORS policy configuration.
 *
 * Encapsulates the full set of Cross-Origin Resource Sharing directives
 * as defined by the Fetch Standard (Living Standard) §3.2. Each property
 * maps directly to a CORS response header.
 *
 * Wildcard handling follows the Fetch Standard's credential-mode rules:
 *
 * - Without credentials: `*` is a true wildcard (any value matches).
 * - With credentials: `*` is treated as the literal string `"*"`,
 *   so specific values MUST be listed explicitly.
 *
 * This applies to allowedOrigins, allowedMethods, allowedHeaders,
 * and exposedHeaders uniformly.
 *
 * @see Fetch Standard §3.2          - CORS protocol
 * @see Fetch Standard §3.2.3        - HTTP responses (header definitions)
 * @see Fetch Standard §3.2.4        - CORS-preflight fetch
 * @see RFC 9110 §9.3.7              - OPTIONS method
 * @see W3C Private Network Access    - Access-Control-Allow-Private-Network
 */
final class CorsConfiguration
{
    /**
     * Normalized allowed origins (lowercase, standard ports stripped).
     *
     * @var list<string>
     */
    public readonly array $allowedOrigins;

    /**
     * Normalized allowed methods (uppercased).
     *
     * @var list<string>
     */
    public readonly array $allowedMethods;

    /**
     * Allowed request headers for preflight validation.
     *
     * Header comparison is case-insensitive per RFC 9110 §5.1.
     * Use `['*']` to allow any header (without credentials) or to
     * reflect requested headers back (with credentials).
     *
     * @var list<string>
     */
    public readonly array $allowedHeaders;

    /**
     * Response headers the browser may expose to client scripts.
     *
     * Maps to the `Access-Control-Expose-Headers` response header.
     * CORS-safelisted response headers (Cache-Control, Content-Language,
     * Content-Length, Content-Type, Expires, Last-Modified, Pragma) are
     * always accessible and need not be listed.
     *
     * @var list<string>
     */
    public readonly array $exposedHeaders;

    /**
     * @param list<string> $allowedOrigins  Origins permitted to make cross-origin
     *                                       requests. Use `['*']` for any origin.
     *                                       Subdomain wildcards (`https://*.example.com`)
     *                                       are supported for pattern matching.
     * @param list<string> $allowedMethods  HTTP methods allowed in preflight.
     *                                       Use `['*']` for any method.
     * @param list<string> $allowedHeaders  Request headers allowed in preflight.
     *                                       Use `['*']` for any header.
     * @param list<string> $exposedHeaders  Response headers exposed to scripts.
     *                                       Use `['*']` for all (without credentials only).
     * @param int|null     $maxAge          Preflight cache duration in seconds.
     *                                       Maps to `Access-Control-Max-Age`. null omits
     *                                       the header (browser applies its default).
     * @param bool         $allowCredentials Whether cookies, Authorization headers,
     *                                       and TLS client certificates are permitted.
     *                                       Maps to `Access-Control-Allow-Credentials`.
     * @param bool         $allowPrivateNetwork Whether requests from public networks
     *                                          to private/local networks are permitted.
     *                                          Maps to `Access-Control-Allow-Private-Network`.
     */
    public function __construct(
        array $allowedOrigins = ['*'],
        array $allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'],
        array $allowedHeaders = [],
        array $exposedHeaders = [],
        public readonly ?int $maxAge = null,
        public readonly bool $allowCredentials = false,
        public readonly bool $allowPrivateNetwork = false,
    ) {
        if ($maxAge !== null && $maxAge < 0) {
            throw new \InvalidArgumentException(
                'Access-Control-Max-Age must be non-negative',
            );
        }

        if ($allowedOrigins === []) {
            throw new \InvalidArgumentException(
                'At least one allowed origin must be configured',
            );
        }

        $this->allowedOrigins = $allowedOrigins;
        $this->allowedMethods = array_values(array_map('strtoupper', $allowedMethods));
        $this->allowedHeaders = $allowedHeaders;
        $this->exposedHeaders = $exposedHeaders;
    }
}

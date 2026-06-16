<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Cross-Origin Resource Sharing (CORS) middleware.
 *
 * Implements the CORS protocol as defined by the Fetch Standard §3.2,
 * handling both preflight and actual cross-origin requests.
 *
 * Request flow:
 *
 * 1. **Preflight requests** (OPTIONS + Origin + Access-Control-Request-Method)
 *    are intercepted and answered directly with a 204 No Content response
 *    containing the appropriate CORS headers. The request is NOT forwarded
 *    to the application handler. Per Fetch Standard §3.2.4, the browser
 *    sends a preflight for non-simple requests to determine whether the
 *    actual request is permitted.
 *
 * 2. **Actual CORS requests** (any method with an Origin header) are
 *    forwarded to the handler, and the response is decorated with
 *    CORS headers if the origin is allowed.
 *
 * 3. **Non-CORS requests** (no Origin header) pass through unchanged,
 *    with only `Vary: Origin` appended for cache correctness.
 *
 * Wildcard handling per the Fetch Standard:
 *
 * - Without credentials: `*` functions as a true wildcard for
 *   Allow-Origin, Allow-Methods, Allow-Headers, and Expose-Headers.
 * - With credentials: `*` is treated as the literal string `"*"`.
 *   The middleware compensates by reflecting the specific origin,
 *   requested method, or requested headers as appropriate.
 *
 * @see Fetch Standard §3.2          - CORS protocol
 * @see Fetch Standard §3.2.3        - HTTP responses
 * @see Fetch Standard §3.2.4        - CORS-preflight fetch
 * @see Fetch Standard §3.2.5        - CORS protocol exceptions
 * @see RFC 9110 §9.3.7              - OPTIONS method
 * @see RFC 9110 §12.5.5             - Vary header
 * @see RFC 6454                      - The Web Origin Concept
 * @see W3C Private Network Access    - Access-Control-Allow-Private-Network
 */
final class CorsMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly CorsConfiguration $config,
        private readonly ResponseFactoryInterface $responseFactory,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        // Preflight: intercept and respond directly (never forwarded to handler)
        if ($this->isPreflightRequest($request)) {
            return $this->handlePreflight($request);
        }

        // Forward to the application handler
        $response = $handler->handle($request);

        // Decorate with CORS headers if this is a cross-origin request
        if ($this->isCorsRequest($request)) {
            $origin = $request->getHeaderLine('Origin');

            if ($this->isOriginAllowed($origin)) {
                $response = $this->addActualRequestHeaders($response, $origin);
            }
        }

        // Always include Vary: Origin for HTTP cache correctness.
        // Without this, a CDN might cache a response without CORS headers
        // and serve it to a cross-origin request, or vice versa.
        // See RFC 9110 §12.5.5 and Fetch Standard §3.2.
        return $this->addVary($response, 'Origin');
    }


    /**
     * Determines whether the request is a CORS request.
     *
     * Per Fetch Standard §3.2, a CORS request is any request that includes
     * an Origin header. Browsers include Origin for cross-origin requests
     * and for same-origin POST/PUT/PATCH/DELETE requests.
     */
    private function isCorsRequest(ServerRequestInterface $request): bool
    {
        return $request->getHeaderLine('Origin') !== '';
    }

    /**
     * Determines whether the request is a CORS preflight request.
     *
     * Per Fetch Standard §3.2.4, a preflight request is an OPTIONS request
     * that includes both an Origin header and an Access-Control-Request-Method
     * header. The browser sends this before making non-simple cross-origin
     * requests to determine if the actual request is permitted.
     */
    private function isPreflightRequest(ServerRequestInterface $request): bool
    {
        return strtoupper($request->getMethod()) === 'OPTIONS'
            && $request->getHeaderLine('Origin') !== ''
            && $request->getHeaderLine('Access-Control-Request-Method') !== '';
    }


    /**
     * Handles a CORS preflight request.
     *
     * Validates the origin, requested method, and requested headers against
     * the configured policy. Returns 204 No Content with CORS headers if
     * permitted, or 403 Forbidden if any check fails.
     *
     * The response always includes Vary headers for cache correctness,
     * even on rejection - a CDN must know that the response depends on
     * the Origin, method, and headers of the request.
     *
     * @see Fetch Standard §3.2.4 - CORS-preflight fetch
     * @see RFC 9110 §9.3.5       - 204 No Content
     * @see RFC 9110 §15.5.4      - 403 Forbidden
     */
    private function handlePreflight(ServerRequestInterface $request): ResponseInterface
    {
        $varyHeaders = ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'];

        $origin = $request->getHeaderLine('Origin');

        // Validate origin
        if (!$this->isOriginAllowed($origin)) {
            return $this->addVary(
                $this->responseFactory->createResponse(403),
                ...$varyHeaders,
            );
        }

        // Validate requested method
        $requestedMethod = $request->getHeaderLine('Access-Control-Request-Method');

        if (!$this->isMethodAllowed($requestedMethod)) {
            return $this->addVary(
                $this->responseFactory->createResponse(403),
                ...$varyHeaders,
            );
        }

        // Validate requested headers
        $requestedHeaders = $this->parseHeaderList(
            $request->getHeaderLine('Access-Control-Request-Headers'),
        );

        if (!$this->areHeadersAllowed($requestedHeaders)) {
            return $this->addVary(
                $this->responseFactory->createResponse(403),
                ...$varyHeaders,
            );
        }

        // Build the successful preflight response
        $response = $this->responseFactory->createResponse(204);

        // Access-Control-Allow-Origin
        $response = $response->withHeader(
            'Access-Control-Allow-Origin',
            $this->resolveAllowOrigin($origin),
        );

        // Access-Control-Allow-Methods
        $response = $response->withHeader(
            'Access-Control-Allow-Methods',
            $this->resolveAllowMethods($requestedMethod),
        );

        // Access-Control-Allow-Headers (only if headers were requested)
        if ($requestedHeaders !== []) {
            $response = $response->withHeader(
                'Access-Control-Allow-Headers',
                $this->resolveAllowHeaders($requestedHeaders),
            );
        }

        // Access-Control-Max-Age
        if ($this->config->maxAge !== null) {
            $response = $response->withHeader(
                'Access-Control-Max-Age',
                (string) $this->config->maxAge,
            );
        }

        // Access-Control-Allow-Credentials
        if ($this->config->allowCredentials) {
            $response = $response->withHeader(
                'Access-Control-Allow-Credentials',
                'true',
            );
        }

        // Access-Control-Allow-Private-Network
        // Per the Private Network Access specification, this header is only
        // sent when the browser explicitly requests it via the corresponding
        // request header.
        if ($this->config->allowPrivateNetwork
            && $request->getHeaderLine('Access-Control-Request-Private-Network') === 'true'
        ) {
            $response = $response->withHeader(
                'Access-Control-Allow-Private-Network',
                'true',
            );
        }

        return $this->addVary($response, ...$varyHeaders);
    }


    /**
     * Adds CORS headers to an actual (non-preflight) cross-origin response.
     *
     * Per Fetch Standard §3.2.3, the browser checks these headers to
     * determine whether the script may read the response.
     */
    private function addActualRequestHeaders(
        ResponseInterface $response,
        string $origin,
    ): ResponseInterface {
        $response = $response->withHeader(
            'Access-Control-Allow-Origin',
            $this->resolveAllowOrigin($origin),
        );

        if ($this->config->allowCredentials) {
            $response = $response->withHeader(
                'Access-Control-Allow-Credentials',
                'true',
            );
        }

        if ($this->config->exposedHeaders !== []) {
            $response = $response->withHeader(
                'Access-Control-Expose-Headers',
                $this->resolveExposeHeaders(),
            );
        }

        return $response;
    }


    /**
     * Determines whether an origin is permitted by the CORS policy.
     *
     * Supports three matching modes:
     *
     * 1. **Wildcard**: `['*']` in allowedOrigins permits any origin.
     * 2. **Exact match**: Origin compared after normalization (lowercase,
     *    standard ports stripped per RFC 6454 §5, userinfo rejected).
     * 3. **Subdomain wildcard**: `https://*.example.com` matches any
     *    subdomain of example.com with the HTTPS scheme.
     *
     * @see RFC 6454 §5 - Comparing Origins
     */
    private function isOriginAllowed(string $origin): bool
    {
        if (in_array('*', $this->config->allowedOrigins, true)) {
            return true;
        }

        $normalized = $this->normalizeOrigin($origin);

        if ($normalized === null) {
            return false;
        }

        foreach ($this->config->allowedOrigins as $allowed) {
            if ($this->isSubdomainWildcard($allowed)) {
                if ($this->matchesSubdomainWildcard($normalized, $allowed)) {
                    return true;
                }
                continue;
            }

            $normalizedAllowed = $this->normalizeOrigin($allowed);

            if ($normalizedAllowed !== null && $normalized === $normalizedAllowed) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalizes an origin to lowercase with standard ports stripped.
     *
     * Per RFC 6454 §5, two origins are the same if and only if their
     * schemes, hosts, and ports are identical. Standard ports (80 for
     * HTTP, 443 for HTTPS) are omitted per RFC 9110 §4.2.3.
     *
     * Origins containing userinfo are rejected as malformed - the
     * origin serialization per RFC 6454 §5 is "scheme://host[:port]"
     * with no userinfo component.
     *
     * @return string|null Normalized origin, or null if malformed
     */
    private function normalizeOrigin(string $origin): ?string
    {
        $parsed = parse_url($origin);

        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            return null;
        }

        // Reject userinfo - not permitted in origin serialization
        if (isset($parsed['user'])) {
            return null;
        }

        $scheme = strtolower($parsed['scheme']);
        $host = strtolower($parsed['host']);
        $normalized = "{$scheme}://{$host}";

        if (isset($parsed['port']) && !$this->isStandardPort($scheme, $parsed['port'])) {
            $normalized .= ':' . $parsed['port'];
        }

        return $normalized;
    }

    /**
     * Determines if a configured origin is a subdomain wildcard pattern.
     *
     * Subdomain wildcards use the syntax `scheme://*.domain[:port]`.
     */
    private function isSubdomainWildcard(string $pattern): bool
    {
        return str_contains($pattern, '://*.');
    }

    /**
     * Matches a normalized origin against a subdomain wildcard pattern.
     *
     * Pattern `https://*.example.com` matches:
     * - `https://sub.example.com`        ✓
     * - `https://deep.sub.example.com`   ✓
     * - `https://example.com`            ✗ (no subdomain)
     * - `http://sub.example.com`         ✗ (wrong scheme)
     *
     * Port handling: if the pattern includes a port, the origin must
     * have the same port. Standard ports are normalized.
     */
    private function matchesSubdomainWildcard(string $normalizedOrigin, string $pattern): bool
    {
        // Derive the base origin by removing the wildcard: "https://*.x.com" -> "https://x.com"
        $schemeSep = strpos($pattern, '://*.');

        if ($schemeSep === false) {
            return false;
        }

        $patternScheme = strtolower(substr($pattern, 0, $schemeSep));
        $patternDomain = strtolower(substr($pattern, $schemeSep + 5)); // after "://*."

        // Normalize port in pattern domain (e.g., "example.com:443" with https -> "example.com")
        $patternBase = $this->normalizeOrigin($patternScheme . '://' . $patternDomain);

        if ($patternBase === null) {
            return false;
        }

        // Extract base after scheme://
        $basePrefix = $patternScheme . '://';

        if (!str_starts_with($normalizedOrigin, $basePrefix)) {
            return false;
        }

        if (!str_starts_with($patternBase, $basePrefix)) {
            return false;
        }

        $originHost = substr($normalizedOrigin, strlen($basePrefix));
        $baseDomain = substr($patternBase, strlen($basePrefix));

        // Origin host must end with ".baseDomain" and have at least one
        // character before the dot (the subdomain component).
        $suffix = '.' . $baseDomain;

        return str_ends_with($originHost, $suffix) && strlen($originHost) > strlen($suffix);
    }


    /**
     * Determines whether a preflight-requested method is allowed.
     */
    private function isMethodAllowed(string $method): bool
    {
        if (in_array('*', $this->config->allowedMethods, true)) {
            return true;
        }

        return in_array(strtoupper($method), $this->config->allowedMethods, true);
    }

    /**
     * Determines whether all preflight-requested headers are allowed.
     *
     * Header names are compared case-insensitively per RFC 9110 §5.1.
     */
    private function areHeadersAllowed(array $requestedHeaders): bool
    {
        if ($requestedHeaders === []) {
            return true;
        }

        if (in_array('*', $this->config->allowedHeaders, true)) {
            return true;
        }

        $allowedLower = array_map('strtolower', $this->config->allowedHeaders);

        foreach ($requestedHeaders as $header) {
            if (!in_array(strtolower(trim($header)), $allowedLower, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Parses a comma-separated header list into individual values.
     *
     * Per RFC 9110 §5.6.1, list-based header field values use commas
     * as delimiters, with optional whitespace.
     *
     * @return list<string>
     */
    private function parseHeaderList(string $value): array
    {
        if ($value === '') {
            return [];
        }

        return array_values(
            array_filter(
                array_map('trim', explode(',', $value)),
                fn(string $v): bool => $v !== '',
            ),
        );
    }


    /**
     * Resolves the Access-Control-Allow-Origin header value.
     *
     * Per the Fetch Standard, when credentials are included:
     * - The `*` wildcard is treated as the literal string, not a wildcard.
     * - The response must include the specific requesting origin.
     *
     * When credentials are not included and all origins are allowed,
     * `*` is sent as a true wildcard to maximize CDN cache efficiency.
     */
    private function resolveAllowOrigin(string $origin): string
    {
        // With credentials: must reflect the specific origin (never *)
        if ($this->config->allowCredentials) {
            return $origin;
        }

        // Without credentials, wildcard -> send literal *
        if (in_array('*', $this->config->allowedOrigins, true)) {
            return '*';
        }

        // Specific origin configured -> reflect the matched origin
        return $origin;
    }

    /**
     * Resolves the Access-Control-Allow-Methods header value.
     *
     * With credentials and wildcard methods: reflects the requested method
     * since `*` is treated literally by the browser.
     *
     * Without credentials and wildcard: sends `*` for efficiency.
     *
     * Otherwise: sends the full configured method list.
     */
    private function resolveAllowMethods(string $requestedMethod): string
    {
        if (in_array('*', $this->config->allowedMethods, true)) {
            if ($this->config->allowCredentials) {
                // Wildcard + credentials: reflect the requested method
                return strtoupper($requestedMethod);
            }

            return '*';
        }

        return implode(', ', $this->config->allowedMethods);
    }

    /**
     * Resolves the Access-Control-Allow-Headers header value.
     *
     * With credentials and wildcard headers: reflects all requested headers
     * back. This is necessary because:
     * 1. `*` is treated literally when credentials are included.
     * 2. The `Authorization` header specifically requires explicit listing
     *    even with `*` in non-credentialed requests per the Fetch Standard.
     *
     * Without credentials and wildcard: sends `*`.
     *
     * Otherwise: sends the configured header list.
     */
    private function resolveAllowHeaders(array $requestedHeaders): string
    {
        if (in_array('*', $this->config->allowedHeaders, true)) {
            if ($this->config->allowCredentials) {
                // Wildcard + credentials: reflect exact requested headers
                return implode(', ', $requestedHeaders);
            }

            return '*';
        }

        return implode(', ', $this->config->allowedHeaders);
    }

    /**
     * Resolves the Access-Control-Expose-Headers header value.
     *
     * Per the Fetch Standard, `*` as a wildcard for exposed headers
     * does not function when credentials are included - it is treated
     * as the literal header name `"*"`.
     */
    private function resolveExposeHeaders(): string
    {
        if (in_array('*', $this->config->exposedHeaders, true)) {
            if (!$this->config->allowCredentials) {
                return '*';
            }

            // With credentials, * is literal - send all configured headers except *
            $headers = array_filter(
                $this->config->exposedHeaders,
                fn(string $h): bool => $h !== '*',
            );

            return implode(', ', $headers);
        }

        return implode(', ', $this->config->exposedHeaders);
    }


    /**
     * Determines whether a port is the default for the given scheme.
     *
     * Per RFC 9110 §4.2.3, the default port for HTTP is 80
     * and for HTTPS is 443. Standard ports are omitted from the
     * origin serialization per RFC 6454 §5.
     */
    private function isStandardPort(string $scheme, int $port): bool
    {
        return match ($scheme) {
            'http' => $port === 80,
            'https' => $port === 443,
            default => false,
        };
    }

    /**
     * Appends values to the Vary response header without duplication.
     *
     * Per RFC 9110 §12.5.5, the Vary header indicates which request
     * header fields were used to select the response representation.
     * This is critical for HTTP caches (CDNs, proxies) to avoid
     * serving incorrect cached responses.
     */
    private function addVary(ResponseInterface $response, string ...$headers): ResponseInterface
    {
        $existing = $response->getHeaderLine('Vary');

        $currentValues = $existing !== ''
            ? array_map('trim', explode(',', $existing))
            : [];

        $currentLower = array_map('strtolower', $currentValues);

        foreach ($headers as $header) {
            if (!in_array(strtolower($header), $currentLower, true)) {
                $currentValues[] = $header;
                $currentLower[] = strtolower($header);
            }
        }

        return $response->withHeader('Vary', implode(', ', $currentValues));
    }
}

<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors;

use InvalidArgumentException;

final readonly class CorsConfiguration
{
    /** @var list<string> */
    public array $allowedOrigins;

    /** @var list<string> */
    public array $allowedMethods;

    /** @var list<string> */
    public array $allowedHeaders;

    /** @var list<string> */
    public array $exposedHeaders;

    /**
     * @param array<array-key, mixed> $allowedOrigins
     * @param array<array-key, mixed> $allowedMethods
     * @param array<array-key, mixed> $allowedHeaders
     * @param array<array-key, mixed> $exposedHeaders
     * @param bool $allowPrivateNetwork Legacy PNA-preflight compatibility only; current LNA is permission-based.
     */
    public function __construct(
        array $allowedOrigins = [],
        array $allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'],
        array $allowedHeaders = [],
        array $exposedHeaders = [],
        public ?int $maxAge = null,
        public bool $allowCredentials = false,
        public bool $allowPrivateNetwork = false,
    ) {
        if ($maxAge !== null && $maxAge < 0) {
            throw new InvalidArgumentException('Access-Control-Max-Age must be non-negative.');
        }

        $this->allowedOrigins = self::normalizeOrigins($allowedOrigins);
        $this->allowedMethods = self::normalizeMethods($allowedMethods);
        $this->allowedHeaders = self::normalizeFieldNames($allowedHeaders, 'allowed request headers');
        $this->exposedHeaders = self::normalizeFieldNames($exposedHeaders, 'exposed response headers');

        if ($allowCredentials) {
            foreach ($this->allowedOrigins as $origin) {
                if ($origin === '*' || str_contains($origin, '://*.')) {
                    throw new InvalidArgumentException(
                        'Credentialed CORS requires explicit non-opaque origins; wildcards and "null" are not allowed.',
                    );
                }
            }

            if (in_array('*', $this->exposedHeaders, true)) {
                throw new InvalidArgumentException(
                    'Credentialed CORS requires explicit exposed response headers; "*" is not a wildcard.',
                );
            }
        }

        if ($allowPrivateNetwork) {
            foreach ($this->allowedOrigins as $origin) {
                if ($origin === '*' || str_contains($origin, '://*.')) {
                    throw new InvalidArgumentException(
                        'Private Network Access requires explicit non-opaque origins.',
                    );
                }
            }
        }
    }

    public function allowsOrigin(Origin $origin): bool
    {
        foreach ($this->allowedOrigins as $allowed) {
            if ($allowed === '*') {
                return !$origin->opaque;
            }

            if (str_contains($allowed, '://*.')) {
                if ($this->matchesSubdomainWildcard($origin, $allowed)) {
                    return true;
                }

                continue;
            }

            $configured = Origin::parse($allowed);

            if ($configured !== null && $configured->equals($origin)) {
                return true;
            }
        }

        return false;
    }

    public function hasOriginWildcard(): bool
    {
        return in_array('*', $this->allowedOrigins, true);
    }

    public function allowsMethod(string $method): bool
    {
        if (!self::validToken($method)) {
            return false;
        }

        return in_array('*', $this->allowedMethods, true)
            || in_array($method, $this->allowedMethods, true);
    }

    /**
     * @param array<array-key, mixed> $headers
     */
    public function allowsHeaders(array $headers): bool
    {
        foreach ($headers as $header) {
            if (!is_string($header) || !self::validToken($header)) {
                return false;
            }

            if (
                !in_array('*', $this->allowedHeaders, true)
                && !in_array(strtolower($header), $this->allowedHeaders, true)
            ) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<array-key, mixed> $origins
     * @return list<string>
     */
    private static function normalizeOrigins(array $origins): array
    {
        $normalized = [];

        foreach ($origins as $origin) {
            if (!is_string($origin) || $origin === '') {
                throw new InvalidArgumentException('Allowed origins must be non-empty strings.');
            }

            $value = self::normalizeOriginPattern($origin);

            if ($value === null) {
                throw new InvalidArgumentException(sprintf('Invalid CORS origin pattern "%s".', $origin));
            }

            if (!in_array($value, $normalized, true)) {
                $normalized[] = $value;
            }
        }

        return $normalized;
    }

    private static function normalizeOriginPattern(string $origin): ?string
    {
        if ($origin === '*') {
            return $origin;
        }

        if ($origin === 'null') {
            return null;
        }

        if (preg_match(
            '/^(https?):\/\/\*\.([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$/iD',
            $origin,
            $matches,
        ) === 1) {
            $scheme = strtolower($matches[1]);
            $domain = strtolower($matches[2]);

            if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
                return null;
            }

            $port = isset($matches[3]) ? (int) $matches[3] : null;

            if ($port !== null && ($port < 1 || $port > 65535)) {
                return null;
            }

            if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
                $port = null;
            }

            return $scheme . '://*.' . $domain . ($port === null ? '' : ':' . $port);
        }

        $parsed = Origin::parse($origin);

        return $parsed === null ? null : (string) $parsed;
    }

    /**
     * @param array<array-key, mixed> $methods
     * @return list<string>
     */
    private static function normalizeMethods(array $methods): array
    {
        $normalized = [];

        foreach ($methods as $method) {
            if (!is_string($method) || ($method !== '*' && !self::validToken($method))) {
                throw new InvalidArgumentException('Allowed CORS methods must be valid HTTP methods or "*".');
            }

            if (!in_array($method, $normalized, true)) {
                $normalized[] = $method;
            }
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $headers
     * @return list<string>
     */
    private static function normalizeFieldNames(array $headers, string $label): array
    {
        $normalized = [];

        foreach ($headers as $header) {
            if (!is_string($header) || ($header !== '*' && !self::validToken($header))) {
                throw new InvalidArgumentException(sprintf(
                    'CORS %s must be valid HTTP field names or "*".',
                    $label,
                ));
            }

            $header = $header === '*' ? '*' : strtolower($header);

            if (!in_array($header, $normalized, true)) {
                $normalized[] = $header;
            }
        }

        return $normalized;
    }

    private static function validToken(string $value): bool
    {
        return $value !== ''
            && preg_match("@^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$@D", $value) === 1;
    }

    private function matchesSubdomainWildcard(Origin $origin, string $pattern): bool
    {
        if ($origin->opaque) {
            return false;
        }

        $separator = strpos($pattern, '://*.');

        if ($separator === false) {
            return false;
        }

        $scheme = substr($pattern, 0, $separator);
        $base = substr($pattern, $separator + 5);
        $originHost = $origin->hostWithPort();

        return $origin->scheme() === $scheme
            && $originHost !== null
            && str_ends_with($originHost, '.' . $base)
            && strlen($originHost) > strlen($base) + 1;
    }
}

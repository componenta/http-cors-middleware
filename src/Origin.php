<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors;

final readonly class Origin implements \Stringable
{
    private function __construct(
        private string $value,
        public bool $opaque,
    ) {}

    public static function parse(string $value): ?self
    {
        if ($value === 'null') {
            return new self('null', true);
        }

        if ($value === '' || trim($value) !== $value || str_contains($value, '@')) {
            return null;
        }

        $parsed = parse_url($value);

        if (
            $parsed === false
            || !isset($parsed['scheme'], $parsed['host'])
            || isset($parsed['user'], $parsed['pass'], $parsed['path'], $parsed['query'], $parsed['fragment'])
        ) {
            return null;
        }

        $scheme = strtolower($parsed['scheme']);

        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }

        $host = strtolower($parsed['host']);

        if (!self::validHost($host)) {
            return null;
        }

        $port = $parsed['port'] ?? null;

        if ($port !== null && ($port < 1 || $port > 65535)) {
            return null;
        }

        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            $port = null;
        }

        return new self(
            $scheme . '://' . $host . ($port === null ? '' : ':' . $port),
            false,
        );
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function scheme(): ?string
    {
        if ($this->opaque) {
            return null;
        }

        $separator = strpos($this->value, '://');

        return $separator === false ? null : substr($this->value, 0, $separator);
    }

    public function hostWithPort(): ?string
    {
        if ($this->opaque) {
            return null;
        }

        $separator = strpos($this->value, '://');

        return $separator === false ? null : substr($this->value, $separator + 3);
    }

    public function __toString(): string
    {
        return $this->value;
    }

    private static function validHost(string $host): bool
    {
        if ($host === '' || preg_match('/[\s\x00-\x1f\x7f]/', $host) === 1) {
            return false;
        }

        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            return filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }

        return filter_var($host, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }
}

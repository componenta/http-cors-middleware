<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Tests;

use Componenta\Http\Middleware\Cors\Origin;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OriginTest extends TestCase
{
    public function testNormalizesSchemeHostAndStandardPort(): void
    {
        $origin = Origin::parse('HTTPS://Example.COM:443');

        self::assertNotNull($origin);
        self::assertSame('https://example.com', (string) $origin);
        self::assertFalse($origin->opaque);
    }

    public function testAcceptsExplicitOpaqueNullOrigin(): void
    {
        $origin = Origin::parse('null');

        self::assertNotNull($origin);
        self::assertSame('null', (string) $origin);
        self::assertTrue($origin->opaque);
    }

    #[DataProvider('invalidSerializedOrigins')]
    public function testRejectsInvalidSerializedOrigin(string $value): void
    {
        self::assertNull(Origin::parse($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidSerializedOrigins(): iterable
    {
        yield 'trailing slash' => ['https://example.com/'];
        yield 'path' => ['https://example.com/path'];
        yield 'query' => ['https://example.com?query=1'];
        yield 'fragment' => ['https://example.com#fragment'];
        yield 'userinfo' => ['https://user@example.com'];
        yield 'userinfo with password' => ['https://user:pass@example.com'];
        yield 'empty' => [''];
        yield 'leading whitespace' => [' null'];
        yield 'unsupported scheme' => ['file://example.com'];
        yield 'missing host' => ['https://'];
        yield 'whitespace in host' => ['https://exa mple.com'];
        yield 'zero port' => ['https://example.com:0'];
    }
}

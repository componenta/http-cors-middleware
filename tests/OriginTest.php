<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Tests;

use Componenta\Http\Middleware\Cors\Origin;
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

    public function testRejectsUriComponentsThatAreNotPartOfSerializedOrigin(): void
    {
        foreach ([
            'https://example.com/',
            'https://example.com/path',
            'https://example.com?query=1',
            'https://example.com#fragment',
            'https://user@example.com',
            'https://user:pass@example.com',
        ] as $value) {
            self::assertNull(Origin::parse($value), $value);
        }
    }

    public function testRejectsUnsupportedOrMalformedOrigins(): void
    {
        foreach ([
            '',
            ' null',
            'file://example.com',
            'https://',
            'https://exa mple.com',
            'https://example.com:0',
        ] as $value) {
            self::assertNull(Origin::parse($value), $value);
        }
    }
}

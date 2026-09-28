<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Tests;

use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\Origin;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class CorsConfigurationTest extends TestCase
{
    public function testDefaultConfigurationDeniesAllOrigins(): void
    {
        $config = new CorsConfiguration();

        self::assertSame([], $config->allowedOrigins);
        self::assertFalse($config->allowsOrigin(Origin::parse('https://example.test') ?? self::fail()));
    }

    public function testCredentialedCorsRequiresExactNonOpaqueOrigins(): void
    {
        foreach ([
            ['*'],
            ['null'],
            ['https://*.example.com'],
        ] as $origins) {
            try {
                new CorsConfiguration(allowedOrigins: $origins, allowCredentials: true);
                self::fail('Expected credentialed wildcard origin to be rejected.');
            } catch (InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function testCredentialedCorsRejectsExposeWildcard(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            exposedHeaders: ['*'],
            allowCredentials: true,
        );
    }

    public function testPrivateNetworkAccessRequiresExactOrigin(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(allowedOrigins: ['*'], allowPrivateNetwork: true);
    }

    public function testOriginPatternsAreNormalizedAndValidated(): void
    {
        $config = new CorsConfiguration(allowedOrigins: [
            'HTTPS://Example.COM:443',
            'https://*.sub.example.com:443',
        ]);

        self::assertSame([
            'https://example.com',
            'https://*.sub.example.com',
        ], $config->allowedOrigins);

        self::assertTrue($config->allowsOrigin(Origin::parse('https://example.com') ?? self::fail()));
        self::assertTrue($config->allowsOrigin(Origin::parse('https://a.sub.example.com') ?? self::fail()));
        self::assertFalse($config->allowsOrigin(Origin::parse('https://sub.example.com') ?? self::fail()));
    }

    public function testRejectsInvalidOriginPattern(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(allowedOrigins: ['https://example.com/path']);
    }

    public function testRejectsInvalidMethodAndHeaderNames(): void
    {
        try {
            new CorsConfiguration(allowedMethods: ["POST\r\nX-Test: yes"]);
            self::fail();
        } catch (InvalidArgumentException) {
            self::addToAssertionCount(1);
        }

        try {
            new CorsConfiguration(allowedHeaders: ['Bad Header']);
            self::fail();
        } catch (InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
    }

    public function testHeaderMatchingIsCaseInsensitive(): void
    {
        $config = new CorsConfiguration(
            allowedOrigins: ['https://example.test'],
            allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
        );

        self::assertSame(['content-type', 'x-csrf-token'], $config->allowedHeaders);
        self::assertTrue($config->allowsHeaders(['CONTENT-TYPE', 'x-csrf-token']));
    }
}

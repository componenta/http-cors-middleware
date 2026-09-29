<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Tests;

use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\Origin;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CorsConfigurationTest extends TestCase
{
    public function testDefaultConfigurationDeniesAllOrigins(): void
    {
        $config = new CorsConfiguration();

        self::assertSame([], $config->allowedOrigins);
        self::assertFalse($config->allowsOrigin(Origin::parse('https://example.test') ?? self::fail()));
    }

    #[DataProvider('credentialedUnsafeOrigins')]
    public function testCredentialedCorsRequiresExactNonOpaqueOrigins(string $origin): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(
            allowedOrigins: [$origin],
            allowCredentials: true,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function credentialedUnsafeOrigins(): iterable
    {
        yield 'wildcard' => ['*'];
        yield 'opaque null' => ['null'];
        yield 'subdomain wildcard' => ['https://*.example.com'];
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
            'HTTPS://*.Sub.Example.COM:443',
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

    #[DataProvider('invalidPolicyTokens')]
    public function testRejectsInvalidPolicyToken(string $kind, string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        match ($kind) {
            'method' => new CorsConfiguration(allowedMethods: [$value]),
            'header' => new CorsConfiguration(allowedHeaders: [$value]),
            default => self::fail('Unknown policy token kind.'),
        };
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidPolicyTokens(): iterable
    {
        yield 'method injection' => ['method', "POST\r\nX-Test: yes"];
        yield 'header with spaces' => ['header', 'Bad Header'];
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

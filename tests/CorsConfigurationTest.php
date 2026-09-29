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

    public function testDefaultMethodsMatchDocumentedSafeBaseline(): void
    {
        $config = new CorsConfiguration();

        self::assertSame(['GET', 'POST', 'HEAD', 'OPTIONS'], $config->allowedMethods);
    }

    public function testMaxAgeAcceptsZeroAndRejectsNegativeValues(): void
    {
        self::assertSame(0, new CorsConfiguration(maxAge: 0)->maxAge);

        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(maxAge: -1);
    }

    #[DataProvider('privateNetworkUnsafeOrigins')]
    public function testPrivateNetworkAccessRequiresExplicitOrigin(string $origin): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(
            allowedOrigins: [$origin],
            allowPrivateNetwork: true,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function privateNetworkUnsafeOrigins(): iterable
    {
        yield 'wildcard' => ['*'];
        yield 'opaque null' => ['null'];
        yield 'subdomain wildcard' => ['https://*.example.com'];
    }

    public function testMethodMatchingIsCaseSensitiveAndDefaultDeny(): void
    {
        $config = new CorsConfiguration(allowedMethods: ['POST', 'X-Custom']);

        self::assertTrue($config->allowsMethod('POST'));
        self::assertTrue($config->allowsMethod('X-Custom'));
        self::assertFalse($config->allowsMethod('post'));
        self::assertFalse($config->allowsMethod('x-custom'));
        self::assertFalse($config->allowsMethod('GET'));
        self::assertFalse($config->allowsMethod("POST\r\nGET"));
    }

    public function testMethodWildcardAllowsAnyValidMethodWithoutChangingCase(): void
    {
        $config = new CorsConfiguration(allowedMethods: ['*']);

        self::assertTrue($config->allowsMethod('PATCH'));
        self::assertTrue($config->allowsMethod('x-Custom'));
        self::assertFalse($config->allowsMethod('BAD METHOD'));
    }

    public function testConfiguredCustomMethodCaseIsPreserved(): void
    {
        $config = new CorsConfiguration(allowedMethods: ['x-Custom']);

        self::assertSame(['x-Custom'], $config->allowedMethods);
    }

    public function testHeaderMatchingRejectsUnknownMalformedAndNonStringValues(): void
    {
        $config = new CorsConfiguration(allowedHeaders: ['content-type']);

        self::assertTrue($config->allowsHeaders(['Content-Type']));
        self::assertFalse($config->allowsHeaders(['X-Other']));
        self::assertFalse($config->allowsHeaders(['Bad Header']));
        self::assertFalse($config->allowsHeaders([123]));
    }

    public function testHeaderWildcardAllowsAnyValidHeaderOnly(): void
    {
        $config = new CorsConfiguration(allowedHeaders: ['*']);

        self::assertTrue($config->allowsHeaders(['X-Anything']));
        self::assertFalse($config->allowsHeaders(["X-Bad\r\nInjected"]));
    }

    #[DataProvider('invalidWildcardOriginPatterns')]
    public function testRejectsMalformedWildcardOriginPattern(string $origin): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CorsConfiguration(allowedOrigins: [$origin]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidWildcardOriginPatterns(): iterable
    {
        yield 'subdomain wildcard' => ['https://*.example.com'];
        yield 'subdomain wildcard with port' => ['https://*.example.com:8443'];
        yield 'prefix garbage' => ['garbagehttps://*.example.com'];
        yield 'suffix garbage' => ['https://*.example.com/path'];
        yield 'port zero' => ['https://*.example.com:0'];
        yield 'port above maximum' => ['https://*.example.com:65536'];
        yield 'empty origin' => [''];
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

    public function testExactOriginPatternsAreNormalizedAndValidated(): void
    {
        $config = new CorsConfiguration(allowedOrigins: [
            'HTTPS://Example.COM:443',
            'https://api.example.com:8443',
        ]);

        self::assertSame([
            'https://example.com',
            'https://api.example.com:8443',
        ], $config->allowedOrigins);
        self::assertTrue($config->allowsOrigin(Origin::parse('https://example.com') ?? self::fail()));
        self::assertTrue($config->allowsOrigin(Origin::parse('https://api.example.com:8443') ?? self::fail()));
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

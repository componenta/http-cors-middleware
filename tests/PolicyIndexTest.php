<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Tests;

use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\Origin;
use PHPUnit\Framework\TestCase;

final class PolicyIndexTest extends TestCase
{
    public function testNormalizedPolicyKeepsExactMatchingSemantics(): void
    {
        $config = new CorsConfiguration(
            allowedOrigins: ['HTTPS://EXAMPLE.TEST:443', 'https://example.test:8443'],
            allowedMethods: ['GET', 'custom'],
            allowedHeaders: ['Authorization', 'X-Custom'],
        );
        foreach (['https://example.test', 'https://example.test:8443'] as $value) {
            $origin = Origin::parse($value);
            self::assertNotNull($origin);
            self::assertTrue($config->allowsOrigin($origin));
        }
        foreach (['http://example.test', 'https://example.test:8444', 'null'] as $value) {
            $origin = Origin::parse($value);
            self::assertNotNull($origin);
            self::assertFalse($config->allowsOrigin($origin));
        }
        self::assertTrue($config->allowsMethod('custom'));
        self::assertFalse($config->allowsMethod('CUSTOM'));
        self::assertTrue($config->allowsHeaders(['authorization', 'X-CUSTOM']));
        self::assertFalse($config->allowsHeaders(['X-Other']));
    }
}

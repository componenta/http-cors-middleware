<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Tests;

use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\CorsMiddleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CorsMiddlewareTest extends TestCase
{
    public function testCredentialedExactOriginIsReflected(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowCredentials: true,
        ));
        $handler = new CorsHandler(new Response(200));

        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example'),
            $handler,
        );

        self::assertSame('https://app.example', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame(1, $handler->calls);
    }

    public function testDisallowedOriginCannotReuseDownstreamCorsHeaders(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://trusted.example'],
        ));
        $handler = new CorsHandler(new Response(200, [
            'Access-Control-Allow-Origin' => '*',
            'Access-Control-Allow-Credentials' => 'true',
            'Access-Control-Expose-Headers' => '*',
        ]));

        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))
                ->withHeader('Origin', 'https://evil.example'),
            $handler,
        );

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
        self::assertFalse($response->hasHeader('Access-Control-Expose-Headers'));
    }

    public function testWildcardOriginWithoutCredentialsUsesWildcardResponse(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(allowedOrigins: ['*']));

        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))
                ->withHeader('Origin', 'https://any.example'),
            new CorsHandler(new Response(200)),
        );

        self::assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
    }

    public function testWildcardDoesNotImplicitlyTrustNullOrigin(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(allowedOrigins: ['*']));

        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))
                ->withHeader('Origin', 'null'),
            new CorsHandler(new Response(200)),
        );

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    public function testExplicitNonCredentialedNullOriginCanBeAllowed(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(allowedOrigins: ['null']));

        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))
                ->withHeader('Origin', 'null'),
            new CorsHandler(new Response(200)),
        );

        self::assertSame('null', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testSuccessfulPreflightIsNotForwardedToHandler(): void
    {
        $handler = new CorsHandler(new Response(500));
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
            allowedHeaders: ['content-type'],
            maxAge: 600,
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'POST')
                ->withHeader('Access-Control-Request-Headers', 'Content-Type'),
            $handler,
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(0, $handler->calls);
        self::assertSame('https://app.example', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('POST', $response->getHeaderLine('Access-Control-Allow-Methods'));
        self::assertSame('content-type', $response->getHeaderLine('Access-Control-Allow-Headers'));
        self::assertSame('600', $response->getHeaderLine('Access-Control-Max-Age'));
    }

    public function testAuthorizationIsExplicitWhenAllowedHeadersUsesWildcard(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
            allowedHeaders: ['*'],
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'POST')
                ->withHeader('Access-Control-Request-Headers', 'Authorization, X-Test'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame('authorization, x-test', $response->getHeaderLine('Access-Control-Allow-Headers'));
    }

    public function testMalformedPreflightHeadersAreRejected(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
            allowedHeaders: ['*'],
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'POST')
                ->withHeader('Access-Control-Request-Headers', 'X-Test, ,Authorization'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame(403, $response->getStatusCode());
    }

    public function testMalformedOriginIsRejectedOnPreflight(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(allowedOrigins: ['*']));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example/path')
                ->withHeader('Access-Control-Request-Method', 'POST'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame(403, $response->getStatusCode());
    }

    public function testPrivateNetworkPermissionVariesOnRequestHeader(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
            allowPrivateNetwork: true,
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'POST')
                ->withHeader('Access-Control-Request-Private-Network', 'true'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Private-Network'));
        self::assertStringContainsString(
            'Access-Control-Request-Private-Network',
            $response->getHeaderLine('Vary'),
        );
    }

    public function testPrivateNetworkRequestIsRejectedWhenNotEnabled(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'POST')
                ->withHeader('Access-Control-Request-Private-Network', 'true'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString(
            'Access-Control-Request-Private-Network',
            $response->getHeaderLine('Vary'),
        );
    }

    public function testExistingVaryWildcardRemainsWildcard(): void
    {
        $middleware = $this->middleware(new CorsConfiguration());

        $response = $middleware->process(
            new ServerRequest('GET', 'https://api.example/data'),
            new CorsHandler(new Response(200, ['Vary' => '*'])),
        );

        self::assertSame('*', $response->getHeaderLine('Vary'));
    }

    private function middleware(CorsConfiguration $config): CorsMiddleware
    {
        return new CorsMiddleware($config, new Psr17Factory());
    }
}

final class CorsHandler implements RequestHandlerInterface
{
    public int $calls = 0;

    public function __construct(
        private readonly ResponseInterface $response,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        ++$this->calls;

        return $this->response;
    }
}

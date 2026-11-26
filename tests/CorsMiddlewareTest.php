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

    public function testActualMethodOutsidePolicyDoesNotExposeResponse(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['PUT'],
        ));
        $handler = new CorsHandler(new Response(200));
        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))->withHeader('Origin', 'https://app.example'),
            $handler,
        );
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertSame(1, $handler->calls);
    }

    public function testEquivalentIpv6OriginIsAllowedAndRequestOriginIsReflected(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://[2001:0db8:0:0:0:0:0:1]'],
            allowCredentials: true,
        ));
        $response = $middleware->process(
            (new ServerRequest('GET', 'https://api.example/data'))->withHeader('Origin', 'https://[2001:db8::1]'),
            new CorsHandler(new Response(200)),
        );
        self::assertSame('https://[2001:db8::1]', $response->getHeaderLine('Access-Control-Allow-Origin'));
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

    public function testOpaqueNullOriginCannotBeAllowlisted(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CorsConfiguration(allowedOrigins: ['null']);
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

    public function testLowercaseOptionsIsNotTreatedAsCorsPreflight(): void
    {
        $handler = new CorsHandler(new Response(209));
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
        ));

        $response = $middleware->process(
            (new ServerRequest('options', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'POST'),
            $handler,
        );

        self::assertSame(209, $response->getStatusCode());
        self::assertSame(1, $handler->calls);
    }

    public function testPreflightMethodMatchingIsCaseSensitive(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['POST'],
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'post'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame(403, $response->getStatusCode());
    }

    public function testCredentialedWildcardPreservesRequestedCustomMethodCase(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowedMethods: ['*'],
            allowCredentials: true,
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://app.example')
                ->withHeader('Access-Control-Request-Method', 'x-Custom'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('x-Custom', $response->getHeaderLine('Access-Control-Allow-Methods'));
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

    public function testRejectedPreflightIsNotCacheable(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://trusted.example'],
            allowedMethods: ['POST'],
        ));

        $response = $middleware->process(
            (new ServerRequest('OPTIONS', 'https://api.example/data'))
                ->withHeader('Origin', 'https://evil.example')
                ->withHeader('Access-Control-Request-Method', 'POST'),
            new CorsHandler(new Response(500)),
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
    }

    public function testPresentButEmptyPreflightFieldsAreRejected(): void
    {
        $middleware = $this->middleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'],
            allowPrivateNetwork: true,
        ));
        foreach ([
            ['Origin' => '', 'Access-Control-Request-Method' => 'POST'],
            ['Origin' => 'https://app.example', 'Access-Control-Request-Method' => ''],
            ['Origin' => 'https://app.example', 'Access-Control-Request-Method' => 'POST', 'Access-Control-Request-Private-Network' => ''],
        ] as $headers) {
            $request = new ServerRequest('OPTIONS', 'https://api.example/data');
            foreach ($headers as $name => $value) {
                $request = $request->withHeader($name, $value);
            }
            $handler = new CorsHandler(new Response(500));
            self::assertSame(403, $middleware->process($request, $handler)->getStatusCode());
            self::assertSame(0, $handler->calls);
        }
    }

    public function testResponseFactoryCannotGrantAdditionalCorsPermissions(): void
    {
        $factory = new class implements \Psr\Http\Message\ResponseFactoryInterface {
            public function createResponse(int $code = 200, string $reasonPhrase = ''): ResponseInterface
            {
                return new Response($code, [
                    'Access-Control-Allow-Origin' => '*',
                    'Access-Control-Allow-Credentials' => 'true',
                    'Access-Control-Allow-Headers' => '*',
                    'Access-Control-Allow-Private-Network' => 'true',
                    'Access-Control-Expose-Headers' => '*',
                    'Access-Control-Max-Age' => '999999',
                    'Vary' => 'Accept-Encoding',
                ]);
            }
        };
        $middleware = new CorsMiddleware(new CorsConfiguration(
            allowedOrigins: ['https://app.example'], allowedMethods: ['POST'],
        ), $factory);
        $request = (new ServerRequest('OPTIONS', 'https://api.example/data'))
            ->withHeader('Origin', 'https://app.example')
            ->withHeader('Access-Control-Request-Method', 'POST');
        $handler = new CorsHandler(new Response(500));
        $response = $middleware->process($request, $handler);
        self::assertSame(204, $response->getStatusCode());
        self::assertSame('https://app.example', $response->getHeaderLine('Access-Control-Allow-Origin'));
        foreach (['Access-Control-Allow-Credentials', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Private-Network', 'Access-Control-Expose-Headers', 'Access-Control-Max-Age'] as $name) {
            self::assertFalse($response->hasHeader($name));
        }
        self::assertStringContainsString('Accept-Encoding', $response->getHeaderLine('Vary'));
        $rejected = $middleware->process($request->withHeader('Origin', 'https://other.example'), $handler);
        self::assertSame(403, $rejected->getStatusCode());
        self::assertFalse($rejected->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($rejected->hasHeader('Access-Control-Allow-Credentials'));
        self::assertSame(0, $handler->calls);
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

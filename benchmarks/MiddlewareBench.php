<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors\Benchmarks;

use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\CorsMiddleware;
use Nyholm\Psr7\Factory\Psr17Factory;
use PhpBench\Attributes as Bench;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

#[Bench\BeforeMethods('setUp')]
#[Bench\Iterations(5)]
#[Bench\Revs(1000)]
final class CorsBench
{
    private CorsMiddleware $middleware;
    private RequestHandlerInterface $handler;
    private ServerRequestInterface $plain;
    private ServerRequestInterface $allowed;
    private ServerRequestInterface $denied;
    private ServerRequestInterface $preflight;
    private ServerRequestInterface $deniedPreflight;
    private array $origins;

    public function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->origins = array_map(static fn(int $i): string => 'https://app' . $i . '.example.test', range(1, 100));
        $this->middleware = new CorsMiddleware($this->configuration(), $factory);
        $this->plain = $factory->createServerRequest('GET', 'https://api.example.test/');
        $this->allowed = $this->plain->withHeader('Origin', 'https://app100.example.test');
        $this->denied = $this->plain->withHeader('Origin', 'https://other.example.test');
        $this->preflight = $factory->createServerRequest('OPTIONS', 'https://api.example.test/')
            ->withHeader('Origin', 'https://app100.example.test')
            ->withHeader('Access-Control-Request-Method', 'POST')
            ->withHeader('Access-Control-Request-Headers', 'authorization, content-type');
        $this->deniedPreflight = $this->preflight->withHeader('Origin', 'https://other.example.test');
        $this->handler = new class($factory->createResponse(200)->withHeader('Vary', 'Accept-Encoding')) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseInterface $response) {}
            public function handle(ServerRequestInterface $request): ResponseInterface { return $this->response; }
        };
    }

    private function configuration(): CorsConfiguration
    {
        return new CorsConfiguration(allowedOrigins: $this->origins, allowedMethods: ['GET', 'POST'],
            allowedHeaders: ['Authorization', 'Content-Type'], allowCredentials: true);
    }

    #[Bench\Revs(100)]
    public function benchConfiguration100Origins(): void { $this->configuration(); }
    public function benchNoOrigin(): void { $this->run($this->plain, 200, false); }
    public function benchAllowedOrigin(): void { $this->run($this->allowed, 200, true); }
    public function benchDeniedOrigin(): void { $this->run($this->denied, 200, false); }
    public function benchAllowedPreflight(): void { $this->run($this->preflight, 204, true); }
    public function benchDeniedPreflight(): void { $this->run($this->deniedPreflight, 403, false); }

    private function run(ServerRequestInterface $request, int $status, bool $hasOrigin): void
    {
        $response = $this->middleware->process($request, $this->handler);
        if ($response->getStatusCode() !== $status || $response->hasHeader('Access-Control-Allow-Origin') !== $hasOrigin) {
            throw new \RuntimeException('Unexpected benchmark response.');
        }
    }
}

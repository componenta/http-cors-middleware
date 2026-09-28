<?php

declare(strict_types=1);

namespace Componenta\Http\Middleware\Cors;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class CorsMiddleware implements MiddlewareInterface
{
    private const array CONTROLLED_RESPONSE_HEADERS = [
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'Access-Control-Allow-Methods',
        'Access-Control-Allow-Headers',
        'Access-Control-Expose-Headers',
        'Access-Control-Max-Age',
        'Access-Control-Allow-Private-Network',
    ];

    public function __construct(
        private CorsConfiguration $config,
        private ResponseFactoryInterface $responseFactory,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        if ($this->isPreflightRequest($request)) {
            return $this->handlePreflight($request);
        }

        $response = $this->stripControlledHeaders($handler->handle($request));
        $originHeader = $request->getHeaderLine('Origin');

        if ($originHeader !== '') {
            $origin = Origin::parse($originHeader);

            if ($origin !== null && $this->config->allowsOrigin($origin)) {
                $response = $this->addActualRequestHeaders($response, $origin);
            }
        }

        return $this->addVary($response, 'Origin');
    }

    private function isPreflightRequest(ServerRequestInterface $request): bool
    {
        return strtoupper($request->getMethod()) === 'OPTIONS'
            && $request->getHeaderLine('Origin') !== ''
            && $request->getHeaderLine('Access-Control-Request-Method') !== '';
    }

    private function handlePreflight(ServerRequestInterface $request): ResponseInterface
    {
        $vary = ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'];
        $privateNetwork = $request->getHeaderLine('Access-Control-Request-Private-Network');

        if ($this->config->allowPrivateNetwork || $privateNetwork !== '') {
            $vary[] = 'Access-Control-Request-Private-Network';
        }

        $origin = Origin::parse($request->getHeaderLine('Origin'));

        if ($origin === null || !$this->config->allowsOrigin($origin)) {
            return $this->preflightRejected($vary);
        }

        $requestedMethod = $request->getHeaderLine('Access-Control-Request-Method');

        if (!$this->config->allowsMethod($requestedMethod)) {
            return $this->preflightRejected($vary);
        }

        $requestedHeaders = $this->parseRequestedHeaders(
            $request->getHeaderLine('Access-Control-Request-Headers'),
        );

        if ($requestedHeaders === null || !$this->config->allowsHeaders($requestedHeaders)) {
            return $this->preflightRejected($vary);
        }

        if ($privateNetwork !== '') {
            if ($privateNetwork !== 'true' || !$this->config->allowPrivateNetwork) {
                return $this->preflightRejected($vary);
            }
        }

        $response = $this->responseFactory->createResponse(204)
            ->withHeader('Access-Control-Allow-Origin', $this->resolveAllowOrigin($origin))
            ->withHeader('Access-Control-Allow-Methods', $this->resolveAllowMethods($requestedMethod));

        if ($requestedHeaders !== []) {
            $response = $response->withHeader(
                'Access-Control-Allow-Headers',
                $this->resolveAllowHeaders($requestedHeaders),
            );
        }

        if ($this->config->maxAge !== null) {
            $response = $response->withHeader('Access-Control-Max-Age', (string) $this->config->maxAge);
        }

        if ($this->config->allowCredentials) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        if ($privateNetwork === 'true' && $this->config->allowPrivateNetwork) {
            $response = $response->withHeader('Access-Control-Allow-Private-Network', 'true');
        }

        return $this->addVary($response, ...$vary);
    }

    /**
     * @param list<string> $vary
     */
    private function preflightRejected(array $vary): ResponseInterface
    {
        return $this->addVary($this->responseFactory->createResponse(403), ...$vary);
    }

    private function addActualRequestHeaders(ResponseInterface $response, Origin $origin): ResponseInterface
    {
        $response = $response->withHeader('Access-Control-Allow-Origin', $this->resolveAllowOrigin($origin));

        if ($this->config->allowCredentials) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        $exposed = $this->resolveExposeHeaders();

        if ($exposed !== null) {
            $response = $response->withHeader('Access-Control-Expose-Headers', $exposed);
        }

        return $response;
    }

    private function resolveAllowOrigin(Origin $origin): string
    {
        if (!$this->config->allowCredentials && $this->config->hasOriginWildcard()) {
            return '*';
        }

        return (string) $origin;
    }

    private function resolveAllowMethods(string $requestedMethod): string
    {
        if (in_array('*', $this->config->allowedMethods, true)) {
            return $this->config->allowCredentials ? strtoupper($requestedMethod) : '*';
        }

        return implode(', ', $this->config->allowedMethods);
    }

    /**
     * @param list<string> $requestedHeaders
     */
    private function resolveAllowHeaders(array $requestedHeaders): string
    {
        if (in_array('*', $this->config->allowedHeaders, true)) {
            $hasAuthorization = in_array('authorization', $requestedHeaders, true);

            if ($this->config->allowCredentials || $hasAuthorization) {
                return implode(', ', $requestedHeaders);
            }

            return '*';
        }

        return implode(', ', $this->config->allowedHeaders);
    }

    private function resolveExposeHeaders(): ?string
    {
        if ($this->config->exposedHeaders === []) {
            return null;
        }

        if (in_array('*', $this->config->exposedHeaders, true)) {
            if (!$this->config->allowCredentials) {
                return '*';
            }

            $explicit = array_values(array_filter(
                $this->config->exposedHeaders,
                static fn(string $header): bool => $header !== '*',
            ));

            return $explicit === [] ? null : implode(', ', $explicit);
        }

        return implode(', ', $this->config->exposedHeaders);
    }

    /**
     * @return list<string>|null
     */
    private function parseRequestedHeaders(string $value): ?array
    {
        if ($value === '') {
            return [];
        }

        $headers = [];

        foreach (explode(',', $value) as $part) {
            $header = trim($part);

            if ($header === '' || preg_match("@^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$@D", $header) !== 1) {
                return null;
            }

            $header = strtolower($header);

            if (!in_array($header, $headers, true)) {
                $headers[] = $header;
            }
        }

        return $headers;
    }

    private function stripControlledHeaders(ResponseInterface $response): ResponseInterface
    {
        foreach (self::CONTROLLED_RESPONSE_HEADERS as $header) {
            $response = $response->withoutHeader($header);
        }

        return $response;
    }

    private function addVary(ResponseInterface $response, string ...$headers): ResponseInterface
    {
        $current = [];

        foreach ($response->getHeader('Vary') as $line) {
            foreach (explode(',', $line) as $part) {
                $value = trim($part);

                if ($value === '') {
                    continue;
                }

                if ($value === '*') {
                    return $response->withHeader('Vary', '*');
                }

                if (!in_array(strtolower($value), array_map('strtolower', $current), true)) {
                    $current[] = $value;
                }
            }
        }

        $lower = array_map('strtolower', $current);

        foreach ($headers as $header) {
            $header = trim($header);

            if ($header === '') {
                continue;
            }

            if ($header === '*') {
                return $response->withHeader('Vary', '*');
            }

            if (!in_array(strtolower($header), $lower, true)) {
                $current[] = $header;
                $lower[] = strtolower($header);
            }
        }

        return $response->withHeader('Vary', implode(', ', $current));
    }
}

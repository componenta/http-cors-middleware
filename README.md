# Componenta HTTP CORS Middleware

PSR-15 middleware for Cross-Origin Resource Sharing. It validates request origins, handles preflight `OPTIONS` requests, and adds CORS response headers.

## Installation

```bash
composer require componenta/http-cors-middleware
```

This package has no config provider. Create `CorsConfiguration` and `CorsMiddleware` explicitly in the application container or route middleware list.

## Quick Start

```php
use Componenta\Http\Middleware\Cors\CorsConfiguration;
use Componenta\Http\Middleware\Cors\CorsMiddleware;

$middleware = new CorsMiddleware(
    config: new CorsConfiguration(
        allowedOrigins: ['https://example.com'],
        allowedMethods: ['GET', 'POST', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        allowCredentials: true,
    ),
    responseFactory: $responseFactory,
);
```

## Configuration

`CorsConfiguration` accepts allowed origins, methods, request headers, exposed headers, optional `maxAge`, `allowCredentials`, and `allowPrivateNetwork`.

`CorsMiddleware` also requires a PSR-17 `ResponseFactoryInterface` to create preflight and rejection responses.

Wildcard origins and headers are supported. When credentials are enabled, wildcard handling follows browser CORS rules and specific values should be configured.

## Boundary

This package only handles CORS. Authentication, CSRF, trusted proxy handling, and rate limiting are separate middleware packages.

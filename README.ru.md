# Componenta HTTP CORS Middleware

PSR-15 промежуточный обработчик для Cross-Origin Resource Sharing. Он проверяет заголовок `Origin`, обрабатывает предварительные `OPTIONS`-запросы и добавляет CORS-заголовки к ответам.

## Граница пакета

Пакет отвечает только за CORS. Аутентификация, CSRF, доверенные прокси и ограничение частоты запросов находятся в отдельных пакетах промежуточных обработчиков.

## Установка

```bash
composer require componenta/http-cors-middleware
```

У пакета нет провайдера конфигурации. Создавайте `CorsConfiguration` и `CorsMiddleware` явно в контейнере приложения или в списке промежуточных обработчиков маршрута.

## Быстрый старт

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

`CorsMiddleware` требует PSR-17 `ResponseFactoryInterface`, чтобы создавать ответы на предварительные запросы и ответы с отказом.

## Конфигурация

`CorsConfiguration` принимает разрешенные источники, методы, заголовки запроса, открываемые заголовки ответа, необязательный `maxAge`, `allowCredentials` и `allowPrivateNetwork`.

Поддерживаются wildcard-значения для источников и заголовков. Когда включены учетные данные, wildcard обрабатывается по правилам браузерного CORS, поэтому обычно лучше задавать конкретные значения.

# Componenta HTTP CORS Middleware

PSR-15 middleware для CORS на PHP 8.4+. Пакет реализует серверную часть CORS-протокола Fetch с консервативной политикой **default deny**.

CORS определяет, может ли JavaScript в браузере прочитать cross-origin ответ. CORS **не является** аутентификацией, авторизацией или защитой от CSRF. Простой cross-origin запрос с запрещённым Origin всё ещё может дойти до приложения — браузер лишь не отдаст ответ вызывающему скрипту.

## Установка

```bash
composer require componenta/http-cors-middleware
```

Пакету нужен PSR-17 `ResponseFactoryInterface`.

## Безопасная конфигурация

По умолчанию не разрешён ни один origin:

```php
$config = new CorsConfiguration(
    allowedOrigins: ['https://app.example.com'],
    allowedMethods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-Request-Id'],
    allowCredentials: true,
    maxAge: 600,
);
```

При `allowCredentials=true` разрешены только точные HTTP(S) origins. Конфигурация отклоняет:

- `*`;
- `null`;
- wildcard поддоменов вида `https://*.example.com`.

Поэтому произвольный или opaque origin нельзя отразить одновременно с `Access-Control-Allow-Credentials: true`.

Без credentials допускается `*`. Он намеренно не включает opaque origin `null`; если он действительно нужен, его следует указать явно и без credentials.

## Разбор Origin

Origin разбирается как serialized origin, а не как произвольный URL:

```text
http://host[:port]
https://host[:port]
```

Userinfo, path, query, fragment, некорректные hosts и порт 0 запрещены. Scheme/host приводятся к нижнему регистру, стандартные порты 80/443 удаляются.

Wildcard поддоменов разрешён только без credentials:

```text
https://*.example.com
```

Он не включает apex-домен. Не используйте широкие wildcard-политики, если хотя бы один sibling subdomain находится вне того же security boundary.

## Preflight

Preflight перехватывается только для `OPTIONS` с `Origin` и `Access-Control-Request-Method`.

Requested method и имена headers проверяются по HTTP token/field-name grammar. Сопоставление HTTP methods регистрозависимое по RFC 9110; регистр custom method сохраняется без нормализации. Malformed или запрещённый preflight получает 403 и не передаётся application handler.

При успехе возвращается 204 с CORS headers.

`Authorization` является CORS non-wildcard request header. Поэтому при `allowedHeaders: ['*']` middleware возвращает его явно, а не полагается на `Access-Control-Allow-Headers: *`.

## Credentials

Credentialed CORS должен быть явным:

```php
new CorsConfiguration(
    allowedOrigins: ['https://app.example.com'],
    allowedMethods: ['POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['X-Request-Id'],
    allowCredentials: true,
);
```

`Access-Control-Expose-Headers: *` с credentials запрещён, потому что Fetch трактует `*` в credential mode как literal value, а не wildcard.

## Private Network Access

PNA включается отдельно и требует точный non-opaque origin. Запрос `Access-Control-Request-Private-Network: true` при выключенном PNA получает 403.

Когда PNA влияет на preflight, ответ добавляет `Vary: Access-Control-Request-Private-Network`.

PNA остаётся развивающейся браузерной спецификацией и не должно использоваться как граница авторизации.

## Владение CORS headers

Middleware удаляет CORS headers, возвращённые downstream handler, и строит их заново только из централизованной policy. Это не позволяет обработчику случайно или намеренно обойти policy через `Access-Control-Allow-Origin: *`.

## Кэширование

Обычные ответы получают `Vary: Origin`. Preflight также варьируется по:

- `Access-Control-Request-Method`;
- `Access-Control-Request-Headers`;
- `Access-Control-Request-Private-Network`, когда он влияет на результат.

Если ответ уже содержит `Vary: *`, он остаётся `Vary: *`.

## Проверка качества

GitHub Actions проверяет:

- PHP 8.4 и 8.5;
- lowest/highest dependency sets;
- `composer validate --strict`;
- `composer audit`;
- PHPStan level max по `src` и `tests`;
- PHPUnit regression tests.

Нормативная модель CORS определяется WHATWG Fetch Living Standard. HTTP syntax/cache semantics — RFC 9110, origin semantics — RFC 6454.

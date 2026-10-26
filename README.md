# Horus PHP SDK

Explicit runtime scopes for PHP 8.2+. Load Composer's autoloader or require `src/Recorder.php`.

```php
use Horus\Recorder;
use Horus\Scope;

$recorder = new Recorder("my-app", ["endpoint" => "http://127.0.0.1:3100"]);
$recorder->trace("request", function (Scope $scope) {
    return $scope->span("orders.process", ["id" => 17], function (Scope $child) {
        $child->checkpoint("order", ["id" => 17]);
        return ["processed" => true];
    });
});
```

Run `php worker.php` separately with the same `HORUS_SPOOL_DIR` as the application. Requests write captures to that private directory; the worker uploads them. Failed uploads remain as `.json.failed`. The spool is bounded; inspect failures before it fills.

Redaction is enabled by default. Pass `["redaction" => false]` in integration code to disable it. Keep the spool private.

Beta packages are not published yet. Maintained by bugdeployer. GPL-3.0-only.

## SSL/TLS certificate due date checker

![](https://github.com/takuya/php-cert-checker/workflows/main/badge.svg)

Check cert is Expired or not.

```php
<?php
use Takuya\PhpCertChecker\CertificateChecker;
//
$checker = new CertificateChecker("twitter.com");
if ($checker->isCertExpired()){
  echo "The Cert is Expired at ". $checker->getExpiredAt();
}
```

## Installing

from github
```sh
composer config repositories.'php-cert-checker' \
         vcs https://github.com/takuya/php-cert-checker  
composer require takuya/php-cert-checker:master
composer install 
```
from packagist
```sh
composer require takuya/php-cert-checker
```

## Testing
```shell
git clone https://github.com/takuya/php-cert-checker
cd php-cert-checker
composer install 
vendor/bin/phpunit
```
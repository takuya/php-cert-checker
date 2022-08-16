## SSL/TLS certificate checker

![](https://github.com/takuya/php-cert-checker/workflows/main/badge.svg)

Check cert is Expired or not.

```php
<?php
use Takuya\PhpCertChecker\CertificateChecker;
//
$checker = new CertificateChecker($domain);
if ($checker->isCertExpired()){
  echo "The Cert is Expired at ". $checker->getExpiredAt();
}
```

## Installing

```sh
composer config repositories.'php-cert-checker' \
         vcs https://github.com/takuya/php-cert-checker  
composer require takuya/php-cert-checker:master
composer install 
```


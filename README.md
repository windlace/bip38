bip38
---
**BIP-38**

#### Install:
```php
composer require cast/bip38
```

#### Usage:
```php
<?php

use function Cast\Crypto\bip38\encrypt;
use function Cast\Crypto\bip38\decrypt;
use function Cast\BaseConv\base58EncodeCheck;
use function Cast\BaseConv\base58DecodeCheck;

$privateKey = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725';
$passphrase = 'TestingOneTwoThree';

$encrypted = encrypt($privateKey, $passphrase, '0142e0');
$encoded   = base58EncodeCheck(hex2bin($encrypted));
$decoded   = bin2hex(base58DecodeCheck($encoded));
$decrypted = decrypt($decoded, $passphrase);
$verified  = hash_equals($privateKey, $decrypted) ? 'true' : 'false'; // true
```

Links:
* https://en.bitcoin.it/wiki/BIP_0038


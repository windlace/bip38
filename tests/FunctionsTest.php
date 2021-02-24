<?php

namespace Cast\Crypto\uint64\Tests;

use PHPUnit\Framework\TestCase;
use function Cast\Crypto\bip38\encrypt;
use function Cast\Crypto\bip38\decrypt;
use function Cast\BaseConv\base58EncodeCheck;
use function Cast\BaseConv\base58DecodeCheck;

class FunctionsTest extends TestCase
{
    public function testEncrypt()
    {
        $privateKey = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725';
        $passphrase = 'TestingOneTwoThree';

        $encrypted = encrypt($privateKey, $passphrase, '0142e0');
        $encoded   = base58EncodeCheck(hex2bin($encrypted));

        $this->assertEquals('0142e06e6b9cece13e15e12aeddb27375d57a2620d02e5f939daf6707f980c1ae2d68b0c5e77d4', $encrypted);
        $this->assertEquals('6PYQSYSQzNXQDxcdG7HqkDGvFeAevC7LQXApFuf3W9oDhJAcThmPYAjkYv', $encoded);
    }

    public function testDecrypt()
    {
        $privateKey = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725';
        $passphrase = 'TestingOneTwoThree';

        $encrypted = '0142e06e6b9cece13e15e12aeddb27375d57a2620d02e5f939daf6707f980c1ae2d68b0c5e77d4';
        $encoded   = '6PYQSYSQzNXQDxcdG7HqkDGvFeAevC7LQXApFuf3W9oDhJAcThmPYAjkYv';

        $decoded   = bin2hex(base58DecodeCheck($encoded));
        $decrypted = decrypt($decoded, $passphrase);;

        $this->assertEquals($encrypted, $decoded);
        $this->assertEquals($privateKey, $decrypted);
    }

}

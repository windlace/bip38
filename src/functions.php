<?php

namespace Cast\Crypto\bip38;

use Exception;
use function Cast\BaseConv\base58Encode;
use function Cast\BaseConv\base58EncodeCheck;
use function Cast\BaseConv\base58DecodeCheck;
use function Cast\Crypto\ECDSA\secp256k1\publicKeyVerbose;
use PhpAes\Aes;

const ADDRESS_PREFIX_BITCOIN_MINENET = '00';
const NON_EC_BASE_58_CHECK_RANGE__WITHOUT_COMPRESSION = 'c0';
const NON_EC_BASE_58_CHECK_RANGE__WITH_COMPRESSION = 'e0';
const SCRYPT_PARAMS = [
    'N' => 16384,
    'r' => 8,
    'p' => 8,
];
const G_X     = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const G_Y     = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

function hash256 ($buffer) {
    return hash('sha256', $buffer);
}

function xorEncrypt($string, $key) {
    $text = $string;
    $outText = '';

    for($i=0; $i<strlen($text); )
    {
        for($j=0; ($j<strlen($key) && $i<strlen($text)); $j++,$i++)
        {
            $outText .= $text{$i} ^ $key{$j};
        }
    }
    return $outText;
}

function addressVerbose(string $publicKey, string $NetworkIdByte)
{
    $sha256PublicKey = hash('sha256', hex2bin($publicKey));
    $ripemd160 = hash('ripemd160', hex2bin($sha256PublicKey));
    $version = $NetworkIdByte;
    $ripemd160WithVersion = $version . $ripemd160;
    $sha256FromRipemd160WithVersion = hash('sha256', hex2bin($ripemd160WithVersion));
    $lastSha256 = hash('sha256', hex2bin($sha256FromRipemd160WithVersion));
    $checksum = substr($lastSha256, 0, 8);
    $binaryAddress = $ripemd160WithVersion . $checksum;
    $address = base58Encode(hex2bin($binaryAddress));

    return compact(
        'sha256PublicKey',
        'ripemd160',
        'version',
        'ripemd160WithVersion',
        'sha256FromRipemd160WithVersion',
        'lastSha256',
        'checksum',
        'binaryAddress',
        'address'
    );
}


/**
 * Bitcoin, non-EC-multiplied
 *
 * @param $privateKey
 * @param $passphrase
 * @param $flags
 * @return string
 * @throws Exception
 */
function encrypt ($privateKey, $passphrase, $flags)
{
    $PublicKey      = publicKeyVerbose($privateKey);
    $compression    = substr($flags, 4, 2);

    $publicKeyCompression = [
        NON_EC_BASE_58_CHECK_RANGE__WITH_COMPRESSION => 'compressed',
        NON_EC_BASE_58_CHECK_RANGE__WITHOUT_COMPRESSION => 'uncompressed'
    ];

    $addressVerbose = addressVerbose($PublicKey[$publicKeyCompression[$compression]], ADDRESS_PREFIX_BITCOIN_MINENET);
    $salt           = substr(hash256(hex2bin(hash256($addressVerbose['address']))), 0, 8);
    $scryptBuf      = scrypt($passphrase, hex2bin($salt), SCRYPT_PARAMS['N'], SCRYPT_PARAMS['r'], SCRYPT_PARAMS['p'], 64);
    $derivedHalf1   = substr($scryptBuf, 0, 64); // 7dcdd9078b432bd490c144ca1f5aa44c1e05bbce9ca8a9ab7243926f487218a4
    $derivedHalf2   = substr($scryptBuf, 64, 128); // d652ef30946ba5b14dd12a07876e86c1b6a73b55a4fe2e0677af6ef2619133ef
    $xorBuf         = xorEncrypt(hex2bin($derivedHalf1), hex2bin($privateKey)); // 652c937ce1735496fa55bcdb585b4384f9715c3738d6858b4798bbcd4e400f81
    $cipherText     = bin2hex((new Aes(hex2bin($derivedHalf2), 'ECB'))->encrypt($xorBuf)); // e13e15e12aeddb27375d57a2620d02e5f939daf6707f980c1ae2d68b0c5e77d4

    return  $flags . $salt . $cipherText;
}

/**
 * @param $encryptedPrivateKey
 * @param $passphrase
 * @return string|null
 * @throws Exception
 */
function decrypt ($encryptedPrivateKey, $passphrase)
{
    if (strlen($encryptedPrivateKey) !== 78)
        throw new Exception('Invalid BIP38 data length');

    if (substr($encryptedPrivateKey, 0, 2) !== '01')
        throw new Exception('Invalid BIP38 prefix');

    //if (substr($encryptedPrivateKey, 2, 2) === '43')
    //    return decryptECMult($encryptedPrivateKey, $passphrase);

    $salt         = substr($encryptedPrivateKey, 6, 8);
    $scryptBuf    = scrypt($passphrase, hex2bin($salt), SCRYPT_PARAMS['N'], SCRYPT_PARAMS['r'], SCRYPT_PARAMS['p'], 64);
    $derivedHalf1 = substr($scryptBuf, 0, 64);
    $derivedHalf2 = substr($scryptBuf, 64, 128);
    $privKeyBuf   = substr($encryptedPrivateKey, 14, 64);
    $decipher     = bin2hex((new Aes(hex2bin($derivedHalf2), 'ECB'))->decrypt(hex2bin($privKeyBuf)));
    $privateKey   = bin2hex(xorEncrypt(hex2bin($decipher),hex2bin($derivedHalf1)));

    return $privateKey;
}

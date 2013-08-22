--TEST--
Crypto\EVP\Cipher::getIVLength basic usage.
--FILE--
<?php
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');

// init first
echo $cipher->getIVLength() . "\n";

?>
--EXPECT--
16

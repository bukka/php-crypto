--TEST--
Crypto\EVP\Cipher::getKeyLength basic usage.
--FILE--
<?php
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');

// init first
echo $cipher->getKeyLength() . "\n";

?>
--EXPECT--
32

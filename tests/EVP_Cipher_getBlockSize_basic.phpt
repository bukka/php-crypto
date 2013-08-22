--TEST--
Crypto\EVP\Cipher::getBlockSize basic usage.
--FILE--
<?php
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');

// init first
echo $cipher->getBlockSize() . "\n";

?>
--EXPECT--
16

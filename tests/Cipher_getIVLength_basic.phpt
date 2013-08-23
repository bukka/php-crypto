--TEST--
Crypto\Cipher::getIVLength basic usage.
--FILE--
<?php
$cipher = new Crypto\Cipher('aes-256-cbc');

// init first
echo $cipher->getIVLength() . "\n";

?>
--EXPECT--
16

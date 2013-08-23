--TEST--
Crypto\Cipher::getKeyLength basic usage.
--FILE--
<?php
$cipher = new Crypto\Cipher('aes-256-cbc');

// init first
echo $cipher->getKeyLength() . "\n";

?>
--EXPECT--
32

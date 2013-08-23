--TEST--
Crypto\Cipher::getBlockSize basic usage.
--FILE--
<?php
$cipher = new Crypto\Cipher('aes-256-cbc');

// init first
echo $cipher->getBlockSize() . "\n";

?>
--EXPECT--
16

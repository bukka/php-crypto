--TEST--
Crypto\Cipher::getMode basic usage.
--FILE--
<?php
$cipher = new Crypto\Cipher('aes-256-cbc');

// init first
echo ($cipher->getMode() == Crypto\Cipher::MODE_CBC ? "CBC" : "ERROR") . "\n";

?>
--EXPECT--
CBC

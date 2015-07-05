--TEST--
Crypto\Cipher::getAlgorithmName basic usage.
--FILE--
<?php
// basic creation
$algorithm = new Crypto\Cipher('aes-256-cbc');
echo $algorithm->getAlgorithmName() . "\n"
?>
--EXPECT--
AES-256-CBC

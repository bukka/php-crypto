--TEST--
Crypto\Hash::getAlgorithmName basic usage.
--FILE--
<?php
// basic creation
$algorithm = new Crypto\Hash('sha256');
echo $algorithm->getAlgorithmName() . "\n"
?>
--EXPECT--
SHA256

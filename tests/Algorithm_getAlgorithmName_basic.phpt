--TEST--
Crypto\Algorithm::getAlgorithmName basic usage.
--FILE--
<?php
// basic creation
$algorithm = new Crypto\Algorithm('custom_alg');
echo $algorithm->getAlgorithmName() . "\n"
?>
--EXPECT--
custom_alg

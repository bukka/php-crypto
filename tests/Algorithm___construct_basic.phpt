--TEST--
Crypto\Algorithm::__construct basic usage.
--FILE--
<?php
// basic creation
$algorithm = new Crypto\Algorithm('custom_alg');
echo $algorithm->getAlgorithmName() . "\n";
?>
--EXCEPT--
custom_alg

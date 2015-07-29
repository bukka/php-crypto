--TEST--
Crypto\HMAC::getAlgorithmName basic usage.
--FILE--
<?php
// basic creation
$hmac = new Crypto\HMAC('key', 'sha256');
echo $hmac->getAlgorithmName() . "\n"
?>
--EXPECT--
SHA256

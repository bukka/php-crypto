--TEST--
Crypto\HMAC::getAlgorithmName basic usage.
--FILE--
<?php
// basic creation
$hmac = new Crypto\HMAC('sha256', 'key');
echo $hmac->getAlgorithmName() . "\n"
?>
--EXPECT--
SHA256

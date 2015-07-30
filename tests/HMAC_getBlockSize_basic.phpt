--TEST--
Crypto\HMAC::getBlockSize basic usage.
--FILE--
<?php
$hmac = new Crypto\HMAC('key', 'sha256');
echo $hmac->getBlockSize() . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
64
SUCCESS

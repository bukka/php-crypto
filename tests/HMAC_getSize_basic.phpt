--TEST--
Crypto\HMAC::getSize basic usage.
--FILE--
<?php
$hmac = new Crypto\HMAC('key', 'sha256');
echo $hmac->getSize() . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
32
SUCCESS

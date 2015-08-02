--TEST--
Crypto\HMAC::update basic usage.
--FILE--
<?php
$hmac = new Crypto\HMAC('key', 'sha256');
$hmac->update('data');
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS

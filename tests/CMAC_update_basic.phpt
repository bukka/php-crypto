--TEST--
Crypto\CMAC::update basic usage.
--FILE--
<?php
$key = pack('H*', '2b7e151628aed2a6abf7158809cf4f3c');

$cmac = new Crypto\CMAC($key, 'aes-128-cbc');
$cmac->update('data');

echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS

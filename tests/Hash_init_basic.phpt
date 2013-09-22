--TEST--
Crypto\Hash::init basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
$hash->init();
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS

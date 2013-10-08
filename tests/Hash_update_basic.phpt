--TEST--
Crypto\Hash::update basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
$hash->update('data');
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS

--TEST--
Crypto\Hash::getBlockSize basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
echo $hash->getBlockSize() . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
64
SUCCESS

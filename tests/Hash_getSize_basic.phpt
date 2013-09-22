--TEST--
Crypto\Hash::getSize basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
echo $hash->getSize() . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
32
SUCCESS

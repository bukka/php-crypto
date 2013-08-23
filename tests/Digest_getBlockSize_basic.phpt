--TEST--
Crypto\Digest::getBlockSize basic usage.
--FILE--
<?php
$digest = new Crypto\Digest('sha256');
echo $digest->getBlockSize() . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
64
SUCCESS

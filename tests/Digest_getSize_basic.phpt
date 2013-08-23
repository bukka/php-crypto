--TEST--
Crypto\Digest::getSize basic usage.
--FILE--
<?php
$digest = new Crypto\Digest('sha256');
echo $digest->getSize() . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
32
SUCCESS

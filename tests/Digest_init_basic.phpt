--TEST--
Crypto\Digest::init basic usage.
--FILE--
<?php
$digest = new Crypto\Digest('sha256');
$digest->init();
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS

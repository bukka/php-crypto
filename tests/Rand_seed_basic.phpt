--TEST--
Crypto\Rand::seed basic usage.
--FILE--
<?php
Crypto\Rand::seed("xxx");
Crypto\Rand::seed("bumbum", 6);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
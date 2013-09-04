--TEST--
Crypto\Rand::cleanup basic usage.
--FILE--
<?php
Crypto\Rand::cleanup();
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
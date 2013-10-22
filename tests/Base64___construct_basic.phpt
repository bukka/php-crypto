--TEST--
Crypto\Base64::__construct basic usage.
--FILE--
<?php
$base64 = new Crypto\Base64;
if ($base64 instanceof Crypto\Base64)
	echo "SUCCESS";

?>
--EXPECT--
SUCCESS

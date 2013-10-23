--TEST--
Crypto\Base64::encodeUpdate basic usage.
--FILE--
<?php
$data = "abcdefghijklmnopqrstuv+**^%$";

// try state exception
$b64 = new Crypto\Base64;
$b64->decodeUpdate("abc");
try {
	$b64->encodeUpdate($data);
}
catch (Crypto\Base64Exception $e) {
	if ($e->getCode() == Crypto\Base64Exception::ENCODE_UPDATE_STATUS) {
		echo "ENCODE UPDATE STATUS EXCEPTION\n";
	}
}

$b64 = new Crypto\Base64;
$b64->encodeUpdate($data);
echo "SUCCESS\n";
?>
--EXPECT--
ENCODE UPDATE STATUS EXCEPTION
SUCCESS
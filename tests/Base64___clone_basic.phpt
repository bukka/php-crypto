--TEST--
Crypto\Base64::__clone basic usage.
--FILE--
<?php
$b64 = new Crypto\Base64;
for ($i = 0; $i < 20; $i++) {
	$b64->encodeUpdate('a');
}
$b64_clone = clone $b64;
for ($i = 0; $i < 10; $i++) {
	$b64->encodeUpdate('b');
}
echo $b64->encodeFinish();
echo $b64_clone->encodeFinish();
?>
--EXPECT--
YWFhYWFhYWFhYWFhYWFhYWFhYWFiYmJiYmJiYmJi
YWFhYWFhYWFhYWFhYWFhYWFhYWE=

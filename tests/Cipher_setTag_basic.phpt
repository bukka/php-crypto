--TEST--
Crypto\Cipher::setTag basic usage.
--SKIPIF--
<?php if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM)) die("Skip: GCM mode not defined (update OpenSSL version)"); ?>
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = hex2bin('622070d3bea6f720943d1198a7e6afa5');
$tag = hex2bin('ed39e13f9a9fdf19036ad2f1ed5d2d1f');

str_repeat('a', 16);

$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setTag('wrong tag');
try {
	echo $cipher->decrypt($data, $key, $iv) . "\n";
}
catch (Crypto\AlgorithmException $e) {
	if (Crypto\AlgorithmException::CIPHER_AUTHENTICATION_FAILED) {
		echo "FAILED\n";
	}
}

$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setTag($tag);
echo $cipher->decrypt($data, $key, $iv) . "\n";

?>
--EXPECT--
FAILED
aaaaaaaaaaaaaaaa
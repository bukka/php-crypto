--TEST--
Crypto\Cipher::setTag in GCM mode basic usage.
--SKIPIF--
<?php
if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM))
	die("Skip: GCM mode not defined (update OpenSSL version)");
?>
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = pack("H*", '622070d3bea6f720943d1198a7e6afa5');
$tag = pack("H*", 'ed39e13f9a9fdf19036ad2f1ed5d2d1f');

$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setTag('wrong tag');
try {
	echo $cipher->decrypt($data, $key, $iv) . "\n";
}
catch (Crypto\CipherException $e) {
	if (Crypto\CipherException::FINISH_FAILED) {
		echo "FAILED\n";
	}
}

$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setTag($tag);
echo $cipher->decrypt($data, $key, $iv) . "\n";


try {
    $cipher->setTag($tag);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_SETTER_FORBIDDEN) {
		echo "FLOW\n";
	}
}

?>
--EXPECT--
FAILED
aaaaaaaaaaaaaaaa
FLOW

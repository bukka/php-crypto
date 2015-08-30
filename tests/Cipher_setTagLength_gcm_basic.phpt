--TEST--
Crypto\Cipher::setTagLength in GCM mode basic usage.
--SKIPIF--
<?php
if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM))
	die("Skip: GCM mode not defined (update OpenSSL version)");
?>
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = str_repeat('a', 16);

$cipher = new Crypto\Cipher('aes-256-gcm');
try {
	$cipher->setTagLength(1);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_LENGTH_LOW) {
		echo "LOW\n";
	}
}

$cipher = new Crypto\Cipher('aes-256-gcm');
try {
	$cipher->setTagLength(100);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_LENGTH_HIGH) {
		echo "HIGH\n";
	}
}

$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->decryptInit($key, $iv);
try {
	$cipher->setTagLength(12);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_LENGTH_SETTER_FORBIDDEN) {
		echo "FLOW\n";
	}
}

$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setTagLength(12);
echo bin2hex($cipher->encrypt($data, $key, $iv)) . "\n";
echo bin2hex($cipher->getTag()) . "\n";


?>
--EXPECT--
LOW
HIGH
FLOW
622070d3bea6f720943d1198a7e6afa5
ed39e13f9a9fdf19036ad2f1

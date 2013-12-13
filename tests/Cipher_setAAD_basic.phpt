--TEST--
Crypto\Cipher::getAAD basic usage.
--SKIPIF--
<?php if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM)) die("Skip: GCM mode not defined (update OpenSSL version)"); ?>
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$data = str_repeat('a', 16);
$aad = str_repeat('b', 16);

// encryption
$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setAAD($aad);
$ct = $cipher->encrypt($data, $key, $iv);
$tag = $cipher->getTag(16);
echo bin2hex($ct) . "\n";

// decryption
$cipher = new Crypto\Cipher('aes-256-gcm');
$cipher->setTag($tag);
$cipher->setAAD($aad);
echo $cipher->decrypt($ct, $key, $iv) . "\n";

// flow exception
try {
	$cipher->setAAD($aad);
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() == Crypto\AlgorithmException::CIPHER_AAD_SETTER_FLOW) {
		echo "CIPHER_AAD_SETTER_FLOW\n";
	}
}


// decryption withou setting AAD
try {
	$cipher = new Crypto\Cipher('aes-256-gcm');
	$cipher->setTag($tag);
	echo $cipher->decrypt($ct, $key, $iv) . "\n";
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() == Crypto\AlgorithmException::CIPHER_FINISH_FAILED) {
		echo "CIPHER_FINISH_FAILED\n";
	}
}



?>
--EXPECT--
622070d3bea6f720943d1198a7e6afa5
aaaaaaaaaaaaaaaa
CIPHER_AAD_SETTER_FLOW
CIPHER_FINISH_FAILED
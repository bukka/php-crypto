--TEST--
Crypto\Cipher::setTagLength in CCM mode basic usage.
--SKIPIF--
<?php
if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_CCM))
	die("Skip: CCM mode not defined (update OpenSSL version)");
?>
--FILE--
<?php
$key = pack("H*", 'ceb009aea4454451feadf0e6b36f45555dd04723baa448e8');
$nonce = pack("H*", '764043c49460b7');

$data =  pack("H*", 'c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310');

$cipher = new Crypto\Cipher('aes-192-ccm');

try {
	$cipher->setTagLength(1);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_LENGTH_LOW) {
		echo "LOW\n";
	}
}

$cipher = new Crypto\Cipher('aes-192-ccm');
try {
	$cipher->setTagLength(100);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_LENGTH_HIGH) {
		echo "HIGH\n";
	}
}

$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->decryptInit($key, $nonce);
try {
	$cipher->setTagLength(12);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_LENGTH_SETTER_FORBIDDEN) {
		echo "FLOW\n";
	}
}

// test encryption
$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTagLength(12);
$ct = $cipher->encrypt($data, $key, $nonce);
echo bin2hex($ct) . "\n";
$tag = $cipher->getTag();
echo bin2hex($tag) . "\n";

// test decryption (if tag is accepted)
$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag($tag);
echo bin2hex($cipher->decrypt($ct, $key, $nonce)) . "\n";

?>
--EXPECT--
LOW
HIGH
FLOW
8a0f3d8229e48e7487fd95a28ad392c80b3681d4fbc7bbfd
b0b16bbb246d585ca392b045
c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310

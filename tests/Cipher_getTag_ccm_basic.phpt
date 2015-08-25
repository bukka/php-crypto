--TEST--
Crypto\Cipher::getTag in CCM mode basic usage.
--SKIPIF--
<?php
if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_CCM)) {
	die("Skip: CCM mode not defined (update OpenSSL version)");
}
?>
--FILE--
<?php
$key = pack("H*", 'ceb009aea4454451feadf0e6b36f45555dd04723baa448e8');
$nonce = pack("H*", '764043c49460b7');

$data =  pack("H*", 'c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310');

$cipher = new Crypto\Cipher('aes-192-ccm');

try {
	$cipher->getTag();
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_GETTER_FORBIDDEN) {
		echo "FLOW\n";
	}
}

// init first
echo bin2hex($cipher->encrypt($data, $key, $nonce)) . "\n";
echo bin2hex($cipher->getTag()) . "\n";


?>
--EXPECT--
FLOW
8a0f3d8229e48e7487fd95a28ad392c80b3681d4fbc7bbfd
3ec1bc9d62356008ce6a4f78f6e3ceb1


--TEST--
Crypto\Cipher::setTag in CCM mode basic usage.
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

$data = pack("H*", '8a0f3d8229e48e7487fd95a28ad392c80b3681d4fbc7bbfd');
$tag = pack("H*", '3ec1bc9d62356008ce6a4f78f6e3ceb1');

$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag('wrong tag');
try {
	echo $cipher->decrypt($data, $key, $nonce) . "\n";
} catch (Crypto\CipherException $e) {
	if (Crypto\CipherException::FINISH_FAILED) {
		echo "WRONG TAG\n";
	}
}

try {
	$cipher = new Crypto\Cipher('aes-192-ccm');
	$cipher->setTag($tag);
	$cipher->decryptInit($key, $nonce);
	$pt = $cipher->decryptUpdate(substr($data, 0, 10));
	$pt .= $cipher->decryptUpdate(substr($data, 10));
} catch (Crypto\CipherException $e) {
	if (Crypto\CipherException::UPDATE_FAILED) {
		echo "MULTI UPDATE\n";
	}
}

// test single decrypt
$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag($tag);
echo bin2hex($cipher->decrypt($data, $key, $nonce)) . "\n";

try {
	$cipher->setTag($tag);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_SETTER_FORBIDDEN) {
		echo "FLOW\n";
	}
}

// test ctx decrypt
$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag($tag);
$cipher->decryptInit($key, $nonce);
$pt = $cipher->decryptUpdate($data);
$pt .= $cipher->decryptFinish();
echo bin2hex($pt) . "\n";

?>
--EXPECT--
WRONG TAG
MULTI UPDATE
c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310
FLOW
c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310

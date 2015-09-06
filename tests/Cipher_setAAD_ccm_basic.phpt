--TEST--
Crypto\Cipher::setAAD in CCM mode basic usage.
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
$aad = pack("H*", '6e80dd7f1badf3a1c9ab25c75f10bde78c23fa0eb8f9aaa53adefbf4cbf78fe4');
$pt = pack("H*", 'c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310');
$ct = pack("H*", '8a0f3d8229e48e7487fd95a28ad392c80b3681d4fbc7bbfd');

// encryption
$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setAAD($aad);
$ct = $cipher->encrypt($pt, $key, $nonce);
$tag = $cipher->getTag();
echo bin2hex($tag) . "\n";
echo bin2hex($ct) . "\n";

// decryption
$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag($tag);
$cipher->setAAD($aad);
echo bin2hex($cipher->decrypt($ct, $key, $nonce)) . "\n";

// flow exception
try {
	$cipher->setAAD($aad);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::AAD_SETTER_FORBIDDEN) {
		echo "CIPHER_AAD_SETTER_FLOW\n";
	}
}


// decryption without setting AAD
try {
	$cipher = new Crypto\Cipher('aes-192-ccm');
	$cipher->setTag($tag);
	echo $cipher->decrypt($ct, $key, $nonce) . "\n";
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() == Crypto\CipherException::TAG_VERIFY_FAILED) {
		echo "TAG_VERIFY_FAILED\n";
	}
}



?>
--EXPECT--
2dd6ef1c45d4ccb723dc074414db506d
8a0f3d8229e48e7487fd95a28ad392c80b3681d4fbc7bbfd
c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310
CIPHER_AAD_SETTER_FLOW
TAG_VERIFY_FAILED

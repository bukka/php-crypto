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
$aad = pack("H*", '6e80dd7f1badf3a1c9ab25c75f10bde78c23fa0eb8f9aaa53adefbf4cbf78fe4');

$data = pack("H*", '8a0f3d8229e48e7487fd95a28ad392c80b3681d4fbc7bbfd');
$tag = pack("H*", '2dd6ef1c45d4ccb723dc074414db506d');

$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag('wrong tag');
try {
	echo $cipher->decrypt($data, $key, $nonce) . "\n";
}
catch (Crypto\CipherException $e) {
	if (Crypto\CipherException::FINISH_FAILED) {
		echo "FAILED\n";
	}
}

$cipher = new Crypto\Cipher('aes-192-ccm');
$cipher->setTag($tag);
$cipher->setAAD($aad);
echo bin2hex($cipher->decrypt($data, $key, $nonce)) . "\n";


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
c8d275f919e17d7fe69c2a1f58939dfe4d403791b5df1310
FLOW
--TEST--
Crypto\HMAC::hexdigest basic usage.
--FILE--
<?php

$msg = "The quick brown fox jumps over the lazy dog";
$key = "key";

function crypto_test_hmac_hexdigest($alg) {
	global $msg, $key;

	echo "$alg\n";
	$hmac = new Crypto\HMAC($key, $alg);
	$hmac->update($msg);
	echo $hmac->hexdigest() . "\n";
}

crypto_test_hmac_hexdigest('md5');
crypto_test_hmac_hexdigest('sha1');
crypto_test_hmac_hexdigest('sha256');
echo "SUCCESS\n";
?>
--EXPECT--
md5
80070713463e7749b90c2dc24911e275
sha1
de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
sha256
f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
SUCCESS

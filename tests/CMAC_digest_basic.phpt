--TEST--
Crypto\CMAC::digest basic usage.
--SKIPIF--
<?php
if (!class_exists('Crypto\CMAC' ))
	die("Skip: CMAC is not supported by OpenSSL");
?>
--FILE--
<?php

$key = pack('H*', '2b7e151628aed2a6abf7158809cf4f3c');

$msg1 = '';

$msg2 = pack('H*', '6bc1bee22e409f96e93d7e117393172a');

$msg3 = pack('H*',
	'6bc1bee22e409f96e93d7e117393172a' .
	'ae2d8a571e03ac9c9eb76fac45af8e51' .
	'30c81c46a35ce411');

$msg4 = pack('H*',
	'6bc1bee22e409f96e93d7e117393172a' .
	'ae2d8a571e03ac9c9eb76fac45af8e51' .
	'30c81c46a35ce411e5fbc1191a0a52ef' .
	'f69f2445df4f9b17ad2b417be66c3710');


function crypto_test_cmac_aes_128($msg) {
	global $key;

	$cmac = new Crypto\CMAC($key, 'AES-128-CBC');
	$cmac->update($msg);
	echo bin2hex($cmac->digest()) . "\n";
}

crypto_test_cmac_aes_128($msg1);
crypto_test_cmac_aes_128($msg2);
crypto_test_cmac_aes_128($msg3);
crypto_test_cmac_aes_128($msg4);
echo "SUCCESS\n";
?>
--EXPECT--
bb1d6929e95937287fa37d129b756746
070a16b46b4d4144f79bdd9dd04a287c
dfa66747de9ae63030ca32611497c827
51f0bebf7e3b9d92fc49741779363cfe
SUCCESS

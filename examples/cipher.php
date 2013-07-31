<?php
namespace Crypto\EVP;
try {
	$cipher = new Cipher('aes_256_ctr');
	$md = new MD('md5');
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

try {
	$cipher->encryptInit("1234");
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}
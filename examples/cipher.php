<?php
namespace Crypto\EVP;
try {
	$md = new MD('md5');

	$cipher = new Cipher('aes-256-ctr');
	$cipher->encryptInit("1234");
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

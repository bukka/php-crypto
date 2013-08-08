<?php
namespace Crypto\EVP;
try {
	$md = new MD('md5');

	$cipher = new Cipher('aes-256-ctr');
	var_dump($cipher->getAlgorithm());
	$key = str_repeat('x', 32);
	$iv = str_repeat('i', 16);
	$cipher->encryptInit($key, $iv);

	$in = "jakub";
	$out = $cipher->encryptUpdate($in);
	$out_final = $cipher->encryptFinal();
	$out .= $out_final;
	var_dump(strlen($out_final));
	var_dump(base64_encode($out));
	var_dump(openssl_encrypt($in, $cipher->getAlgorithm(), $key, 0, $iv));
	var_dump(openssl_decrypt($out, $cipher->getAlgorithm(), $key, OPENSSL_RAW_DATA, $iv));
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

<?php
namespace Crypto;
try {
	$md = new Digest('md5');

	$cipher = new Cipher('aes-256-ctr');
	var_dump($cipher->getAlgorithm());
	$key = str_repeat('x', 32);
	$iv = str_repeat('i', 16);

	$in = "jakub";
	// stream encryption
	$cipher->encryptInit($key, $iv);
	$stream_out = $cipher->encryptUpdate($in);
	$stream_out_final = $cipher->encryptFinal();
	$stream_out .= $stream_out_final;
	// complete encryption
	$out = $cipher->encrypt($in, $key, $iv);
	var_dump(base64_encode($stream_out));
	var_dump(base64_encode($out));
	var_dump($cipher->decrypt($out, $key, $iv));
	// openssl ext functions result
	echo "STANDARD RESULT\n";
	var_dump(openssl_encrypt($in, $cipher->getAlgorithm(), $key, 0, $iv));
	var_dump(openssl_decrypt($out, $cipher->getAlgorithm(), $key, OPENSSL_RAW_DATA, $iv));
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

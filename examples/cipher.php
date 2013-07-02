<?php
namespace Crypto\EVP;
$cipher = new Cipher('des_ecb');
$md = new MD('md5');

var_dump($cipher->getAlgorithm());
var_dump($md->getAlgorithm());

try {
	$c2 = new Cipher('xxx');
}
catch(InvalidAlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}
<?php
namespace Crypto\EVP;
$cipher = new Cipher('des_ecb');
$md = new MD('md5');

var_dump($cipher->getAlgorithm());
var_dump($md->getAlgorithm());
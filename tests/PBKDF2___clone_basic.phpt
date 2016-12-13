--TEST--
Crypto\PBKDF2::__clone basic usage.
--SKIPIF--
<?php if (!class_exists('Crypto\PBKDF2')) die("Skip: PBKDF2 is not supported (update OpenSSL version)"); ?>
--FILE--
<?php
function print_pbkdf2($kdf) {
	var_dump($kdf->getHashAlgorithm());
	var_dump($kdf->getIterations());
}

$pbkdf2 = new Crypto\PBKDF2('sha256', 32, 'salt', 900);
$pbkdf2_clone = clone $pbkdf2;
print_pbkdf2($pbkdf2_clone);
$pbkdf2->setHashAlgorithm('sha1');
$pbkdf2->setIterations(990);
print_pbkdf2($pbkdf2);
print_pbkdf2($pbkdf2_clone);
$pbkdf2_clone->setHashAlgorithm('sha512');
$pbkdf2_clone->setIterations(500);
print_pbkdf2($pbkdf2);
print_pbkdf2($pbkdf2_clone);
?>
--EXPECT--
string(6) "SHA256"
int(900)
string(4) "SHA1"
int(990)
string(6) "SHA256"
int(900)
string(4) "SHA1"
int(990)
string(6) "SHA512"
int(500)

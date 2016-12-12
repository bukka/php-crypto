--TEST--
Crypto\KDF::__clone basic usage.
--FILE--
<?php
function print_kdf($kdf) {
    var_dump($kdf->getSalt());
	var_dump($kdf->getLength());
}

class SubKDF extends Crypto\KDF {
    function __construct($length, $salt) {
	    parent::__construct($length, $salt);
	}
	function derive($password) {
		return sha1($password);
	}
}
$subkdf = new SubKDF(32, 'salt');
$subkdf_clone = clone $subkdf;
print_kdf($subkdf_clone);
$subkdf->setSalt('different_salt');
$subkdf->setLength(24);
print_kdf($subkdf);
print_kdf($subkdf_clone);
$subkdf_clone->setSalt('clone_salt');
$subkdf_clone->setLength(20);
print_kdf($subkdf);
print_kdf($subkdf_clone);
?>
--EXPECT--
string(4) "salt"
int(32)
string(14) "different_salt"
int(24)
string(4) "salt"
int(32)
string(14) "different_salt"
int(24)
string(10) "clone_salt"
int(20)

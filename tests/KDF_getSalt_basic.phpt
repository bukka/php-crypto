--TEST--
Crypto\KDF::getSalt basic usage.
--FILE--
<?php
// sub classing
class SubKDF extends Crypto\KDF {
    function __construct($length, $salt) {
	    parent::__construct($length, $salt);
	}
	function derive($password) {
		return sha1($password);
	}
}
$subkdf = new SubKDF(32, 'salt');
var_dump($subkdf->getSalt());
?>
--EXPECT--
string(4) "salt"

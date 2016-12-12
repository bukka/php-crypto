--TEST--
Crypto\KDF::setSalt basic usage.
--FILE--
<?php
// sub classing
class SubKDF extends Crypto\KDF {
    function __construct() {
	    parent::__construct(32);
	}
	function derive($password) {
		return sha1($password);
	}
}
$subkdf = new SubKDF();
var_dump($subkdf->getSalt());
var_dump($subkdf->setSalt('salt'));
var_dump($subkdf->getSalt());
?>
--EXPECT--
NULL
bool(true)
string(4) "salt"

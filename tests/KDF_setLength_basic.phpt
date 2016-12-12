--TEST--
Crypto\KDF::setLength basic usage.
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
var_dump($subkdf->getLength());
var_dump($subkdf->setLength(25));
var_dump($subkdf->getLength());
?>
--EXPECT--
int(32)
bool(true)
int(25)

--TEST--
Crypto\KDF::getSalt basic usage.
--FILE--
<?php
// sub classing
class SubKDF extends Crypto\KDF {
    function __construct($salt) {
	    parent::__construct($salt);
	}
}
$subkdf = new SubKDF('salt');
var_dump($subkdf->getSalt());
?>
--EXPECT--
string(4) "salt"

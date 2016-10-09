--TEST--
Crypto\KDF::setSalt basic usage.
--FILE--
<?php
// sub classing
class SubKDF extends Crypto\KDF {
    function __construct() {
	    parent::__construct();
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

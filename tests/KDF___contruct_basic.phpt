--TEST--
Crypto\KDF::__construct basic usage.
--FILE--
<?php
// sub classing
class SubKDF extends Crypto\KDF {
    function __construct($salt) {
	    parent::__construct($salt);
	}
}
$subkdf = new SubKDF('salt');
var_dump($subkdf);
?>
--EXPECTF--
object(SubKDF)#%d (0) {
}

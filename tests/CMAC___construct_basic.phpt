--TEST--
Crypto\CMAC::__construct basic usage.
--SKIPIF--
<?php
if (!class_exists('Crypto\CMAC' ))
	die("Skip: CMAC is not supported by OpenSSL");
?>
--FILE--
<?php
$key = pack('H*', '2b7e151628aed2a6abf7158809cf4f3c');

// basic creation
$cmac = new Crypto\CMAC($key, 'aes-128-cbc');
if ($cmac instanceof Crypto\CMAC) {
	echo "FOUND\n";
}
// invalid key
try {
	$cmac = new Crypto\CMAC('key', 'aes-128-cbc');
}
catch (Crypto\MACException $e) {
	if ($e->getCode() === Crypto\MACException::KEY_LENGTH_INVALID) {
		echo "KEY LENGTH INVALID\n";
	}
}
// invalid creation
try {
	$cmac = new Crypto\CMAC($key, 'nnn');
}
catch (Crypto\MACException $e) {
	if ($e->getCode() === Crypto\MACException::MAC_ALGORITHM_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubCMAC extends Crypto\CMAC {
	function __construct($key, $algorithm) {
		parent::__construct($key, $algorithm);
		echo $this->algorithm . "\n";
	}
}
$subcmac = new SubCMAC($key, 'aes-128-cbc');
?>
--EXPECT--
FOUND
KEY LENGTH INVALID
NOT FOUND
AES-128-CBC

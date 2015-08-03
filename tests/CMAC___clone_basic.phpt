--TEST--
Crypto\CMAC::__clone basic usage.
--SKIPIF--
<?php
if (!class_exists('Crypto\CMAC' ))
	die("Skip: CMAC is not supported by OpenSSL");
?>
--FILE--
<?php
$key = pack('H*', '2b7e151628aed2a6abf7158809cf4f3c');
$data1 = pack('H*', '6bc1bee22e409f96e93d7e117393172a');
$data2 = pack('H*', 'ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411');

$cmac = new Crypto\CMAC($key, 'aes-128-cbc');
$cmac->update($data1);
$cmac_clone = clone $cmac;
echo $cmac_clone->getAlgorithmName() . "\n";

$cmac->update($data2);
echo $cmac->hexdigest() . "\n";

$cmac_clone->update($data2);
echo $cmac_clone->hexdigest() . "\n";

echo "SUCCESS\n";
?>
--EXPECT--
AES-128-CBC
dfa66747de9ae63030ca32611497c827
dfa66747de9ae63030ca32611497c827
SUCCESS

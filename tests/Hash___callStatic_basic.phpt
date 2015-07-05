--TEST--
Crypto\Hash::__callStatic basic usage.
--FILE--
<?php

$data = "data";
$hash = Crypto\Hash::sha256();
$hash->update($data);
echo $hash->getAlgorithmName() . "\n";
echo $hash->hexdigest() . "\n";

echo Crypto\Hash::sha256($data)->hexdigest() . "\n";
$int_data = 23;
echo Crypto\Hash::sha256($int_data)->hexdigest() . "\n";
if (!is_int($int_data))
	echo "ERROR\n";

try {
	Crypto\Hash::non_existant();
}
catch (Crypto\HashException $e) {
	if ($e->getCode() === Crypto\HashException::STATIC_METHOD_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}

echo "SUCCESS\n";
?>
--EXPECT--
SHA256
3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
535fa30d7e25dd8a49f1536779734ec8286108d115da5045d77f3b4185d8f790
NOT FOUND
SUCCESS

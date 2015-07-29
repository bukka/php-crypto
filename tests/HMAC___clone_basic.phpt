--TEST--
Crypto\HMAC::__clone basic usage.
--FILE--
<?php
$data1 = "The quick brown fox ";
$data2 = "jumps over the lazy dog";

$hmac = new Crypto\HMAC('key', 'sha256');
$hmac->update($data1);
$hmac_clone = clone $hmac;
echo $hmac_clone->getAlgorithmName() . "\n";

$hmac->update($data2);
echo $hmac->hexdigest() . "\n";

$hmac_clone->update($data2);
echo $hmac_clone->hexdigest() . "\n";

echo "SUCCESS\n";
?>
--EXPECT--
SHA256
f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
SUCCESS

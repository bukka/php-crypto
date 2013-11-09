--TEST--
Crypto\Hash::__clone basic usage.
--FILE--
<?php
$data1 = "data1";
$data2 = "data2";

$hash = new Crypto\Hash('sha256');
$hash->update($data1);
$hash_clone = clone $hash;
echo $hash_clone->getAlgorithmName() . "\n";

$hash->update($data2);
echo $hash->hexdigest() . "\n";

$hash_clone->update($data2);
echo $hash_clone->hexdigest() . "\n";

echo "SUCCESS\n";
?>
--EXPECT--
SHA256
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
SUCCESS

--TEST--
Crypto\Hash::getAlgorithms basic usage.
--FILE--
<?php
$algorithms_all = Crypto\Hash::getAlgorithms();
if (is_array($algorithms_all) && !empty($algorithms_all))
	echo "ALL\n";
$algorithms_aliases = Crypto\Hash::getAlgorithms(true);
if (is_array($algorithms_aliases) && !empty($algorithms_aliases))
	echo "ALIASES\n";
$algorithms_sha = Crypto\Hash::getAlgorithms(false, 'SHA');
foreach ($algorithms_sha as $algorithm_sha) {
	echo $algorithm_sha . "\n";
}

?>
--EXPECT--
ALL
ALIASES
SHA
SHA1
SHA224
SHA256
SHA384
SHA512

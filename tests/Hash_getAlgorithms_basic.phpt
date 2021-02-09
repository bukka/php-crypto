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
if (is_array($algorithms_sha) && count($algorithms_sha) > 0)
	echo "SHA\n";

?>
--EXPECT--
ALL
ALIASES
SHA

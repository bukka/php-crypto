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
$algorithms_aes = Crypto\Hash::getAlgorithms(false, 'SHA');
if (is_array($algorithms_aes) && !empty($algorithms_aes))
	echo "AES\n";
?>
--EXPECT--
ALL
ALIASES
AES
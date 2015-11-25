--TEST--
Crypto\Cipher::getAlgorithms basic usage.
--FILE--
<?php
$algorithms_all = Crypto\Cipher::getAlgorithms();
if (is_array($algorithms_all) && !empty($algorithms_all))
	echo "ALL\n";
$algorithms_aliases = Crypto\Cipher::getAlgorithms(true);
if (is_array($algorithms_aliases) && !empty($algorithms_aliases))
	echo "ALIASES\n";
$algorithms_aes = Crypto\Cipher::getAlgorithms(false, 'AES');
if (is_array($algorithms_aes) && !empty($algorithms_aes))
	echo "AES\n";
?>
--EXPECT--
ALL
ALIASES
AES
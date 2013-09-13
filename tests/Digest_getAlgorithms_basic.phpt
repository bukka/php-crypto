--TEST--
Crypto\Digest::getAlgorithms basic usage.
--FILE--
<?php
$algorithms_all = Crypto\Digest::getAlgorithms();
if (is_array($algorithms_all) && !empty($algorithms_all))
	echo "ALL\n";
$algorithms_aliases = Crypto\Digest::getAlgorithms(true);
if (is_array($algorithms_aliases) && !empty($algorithms_aliases))
	echo "ALIASES\n";
$algorithms_aes = Crypto\Digest::getAlgorithms(false, 'SHA');
if (is_array($algorithms_aes) && !empty($algorithms_aes))
	echo "AES\n";
?>
--EXPECT--
ALL
ALIASES
AES
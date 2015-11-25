--TEST--
Crypto\Cipher::getAlgorithms in CCM mode basic usage.
--SKIPIF--
<?php
if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_CCM))
	die("Skip: CCM mode not defined (update OpenSSL version)");
?>
--FILE--
<?php
$algos = Crypto\cipher::getAlgorithms();
foreach ($algos as $algo) {
	if (substr($algo, -3) == 'ccm') {
		echo "$algo\n";
	}
}
?>
Done
--EXPECT--
aes-128-ccm
aes-192-ccm
aes-256-ccm
Done
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
$count = 0;
foreach ($algos as $algo) {
	if (substr($algo, -3) == 'ccm') {
		$count++;
	}
}
if($count === 0){
	echo "ERROR: no algorithms found\n";
}
?>
Done
--EXPECT--
Done

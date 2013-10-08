<?php
namespace Crypto;

$algorithm = 'sha256';

if (!Hash::hasAlgorithm($algorithm)) {
	die("Algorithm $algorithm not found" . PHP_EOL);
}

try {
	$hash = new Hash($algorithm);

	// Algorithm method for retrieving algorithm
	echo "Algorithm: " . $hash->getAlgorithmName() . PHP_EOL;

	// Params
	echo "Size: " . $hash->getSize() . PHP_EOL;
	echo "Block size: " . $hash->getBlockSize() . PHP_EOL;

	// Test data
	$data1 = "Test";
	$data2 = "Data";
	$data = $data1 . $data2;

	// Simple hash
	$hash->update($data);
	$sim_hash = $hash->hexdigest();
	
	// init/update/final hash
	$hash = new Hash($algorithm);
	$hash->update($data1);
	$hash->update($data2);
	$iuf_hash = $hash->hexdigest();

	// Raw data output (used hex format for printing)
	echo "Hash (sim): " . $sim_hash . PHP_EOL;
	echo "Hash (iuf): " . $iuf_hash . PHP_EOL;
	// sim == iuf
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

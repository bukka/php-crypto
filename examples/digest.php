<?php
namespace Crypto;

$algorithm = 'sha256';

if (!Digest::hasAlgorithm($algorithm)) {
	die("Algorithm $algorithm not found" . PHP_EOL);
}

try {
	$digest = new Digest($algorithm);

	// Algorithm method for retrieving algorithm
	echo "Algorithm: " . $digest->getAlgorithm() . PHP_EOL;

	// Params
	echo "Size: " . $digest->getSize() . PHP_EOL;
	echo "Block size: " . $digest->getBlockSize() . PHP_EOL;

	// Test data
	$data1 = "Test";
	$data2 = "Data";
	$data = $data1 . $data2;

	// Simple digest
	$sim_digest = $digest->make($data);
	
	// init/update/final digest
	$digest->init();
	$digest->update($data1);
	$digest->update($data2);
	$iuf_digest = $digest->final();

	// Raw data output (used hex format for printing)
	echo "Digest (sim): " . bin2hex($sim_digest) . PHP_EOL;
	echo "Digest (iuf): " . bin2hex($iuf_digest) . PHP_EOL;
	// sim == iuf
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

<?php
use Crypto\Hash;
use Crypto\AlgorihtmException;

namespace Crypto;

$algorithm = 'sha256';

if (!Hash::hasAlgorithm($algorithm)) {
	die("Algorithm $algorithm not found" . PHP_EOL);
}

try {
	// create Hash object
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

	// Simple hash (object created using static method)
	$hash = Hash::sha256();
	$hash->update($data);
	$sim_hash = $hash->hexdigest();
	
	// init/update/final hash
	$hash->update($data1);
	$hash->update($data2);
	$iuf_hash = $hash->hexdigest();

	// Create hash in one expression
	$one_hash = Hash::sha256($data)->hexdigest();
	
	// Raw data output (used hex format for printing)
	echo "Hash (sim): " . $sim_hash . PHP_EOL;
	echo "Hash (iuf): " . $iuf_hash . PHP_EOL;
	echo "Hash (one): " . $one_hash . PHP_EOL;
	// sim = iuf = con 
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}

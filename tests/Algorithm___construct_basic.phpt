--TEST--
Crypto\Algorithm::__construct basic usage.
--FILE--
<?php
// basic creation
$algorithm = new Crypto\Algorithm('custom_alg');
if ($algorithm instanceof Crypto\Algorithm)
	echo "created\n";

// sub classing
class SubAlgorithm extends Crypto\Algorithm {
	function __construct($algorithm) {
		parent::__construct($algorithm);
		echo $this->algorithm . "\n";
	}
}
$subalg = new SubAlgorithm('custom_subalg');
?>
--EXPECT--
created
CUSTOM_SUBALG

--TEST--
Crypto\PBKDF2::setHashAlgorithm basic usage.
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256', 32);
$pbkdf2->setHashAlgorithm('sha512');
echo $pbkdf2->getHashAlgorithm() . "\n";

try {
    $pbkdf2->setHashAlgorithm('invalid');
}
catch (Crypto\PBKDF2Exception $e) {
    if ($e->getCode() === Crypto\PBKDF2Exception::HASH_ALGORITHM_NOT_FOUND) {
	    echo "HASH NOT FOUND\n";
	}
}
?>
--EXPECT--
SHA512
HASH NOT FOUND

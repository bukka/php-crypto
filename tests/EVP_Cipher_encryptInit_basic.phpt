--TEST--
Crypto\EVP\Cipher::encryptInit basic usage.
--FILE--
<?php
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

// key length
try {
	$cipher->encryptInit('short_key', $iv);
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_KEY_LENGTH) {
		echo "SHORT KEY\n";
	}
}

// iv length
try {
	$cipher->encryptInit($key, 'short_iv');
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_IV_LENGTH) {
		echo "SHORT IV\n";
	}
}

// iv empty when required
try {
	$cipher->encryptInit($key);
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_IV_LENGTH) {
		echo "NO IV\n";
	}
}

// both
try {
	$cipher->encryptInit('short_key');
}
catch (Crypto\EVP\AlgorithmException $e) {
	// key checking is first
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_KEY_LENGTH) {
		echo "BOTH\n";
	}
}

$cipher->encryptInit($key, $iv);
echo "SUCCESS\n";
?>
--EXPECT--
SHORT KEY
SHORT IV
NO IV
BOTH
SUCCESS

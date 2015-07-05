--TEST--
Crypto\Cipher::encryptInit basic usage.
--FILE--
<?php
$cipher = new Crypto\Cipher('aes-256-cbc');
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

// key length
try {
	$cipher->encryptInit('short_key', $iv);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::KEY_LENGTH_INVALID) {
		echo "SHORT KEY\n";
	}
}

// iv length
try {
	$cipher->encryptInit($key, 'short_iv');
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::IV_LENGTH_INVALID) {
		echo "SHORT IV\n";
	}
}

// iv empty when required
try {
	$cipher->encryptInit($key);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::IV_LENGTH_INVALID) {
		echo "NO IV\n";
	}
}

// both
try {	
	$cipher->encryptInit('short_key');
}
catch (Crypto\CipherException $e) {
	// key checking is first
	if ($e->getCode() === Crypto\CipherException::KEY_LENGTH_INVALID) {
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

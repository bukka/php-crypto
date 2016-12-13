--TEST--
Crypto\PBKDF2::__construct basic usage.
--SKIPIF--
<?php if (!class_exists('Crypto\PBKDF2')) die("Skip: PBKDF2 is not supported (update OpenSSL version)"); ?>
--FILE--
<?php
// basic creation with just hash algorithm parameter
$pbkdf2 = new Crypto\PBKDF2('sha256', 32);
if ($pbkdf2 instanceof Crypto\PBKDF2) {
    echo "HASH ONLY\n";
}

// invalid creation
try {
    $pbkdf2 = new Crypto\PBKDF2('nnn', 32);
}
catch (Crypto\PBKDF2Exception $e) {
    if ($e->getCode() === Crypto\PBKDF2Exception::HASH_ALGORITHM_NOT_FOUND) {
	    echo "HASH NOT FOUND\n";
	}
}

// basic creation with just hash algorithm and salt
$pbkdf2 = new Crypto\PBKDF2('sha256', 32, 'salt');
if ($pbkdf2 instanceof Crypto\PBKDF2) {
    echo "HASH AND SALT\n";
}
$pbkdf2 = new Crypto\PBKDF2('sha256', 32, 'salt', 900);
if ($pbkdf2 instanceof Crypto\PBKDF2) {
    echo "HASH, SALT AND ITERATIONS\n";
}
?>
--EXPECT--
HASH ONLY
HASH NOT FOUND
HASH AND SALT
HASH, SALT AND ITERATIONS

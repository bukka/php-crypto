# PHP OpenSSL Crypto wrapper

The php-crypto is an objective wrapper for OpenSSL Crypto library.


## Installation

First download the source
```
git clone https://github.com/bukka/php-crypto.git
```

Before you start installation make sure that you have `OpenSSL` library installed. It is defaultly installed on the most Linux distribution.

Currently you need to have PHP compiled with OpenSSL extension (`--with-openssl`). This dependency will be removed in the future.

Then go to the created source directory and compile the extension. You need to have a php development package installed (command `phpize` must be available).
```
cd php-crypto
phpize
./configure --with-crypto
make
sudo make install
```

Finally you need to add
```
extension=crypto.so
```
to the `php.ini`


## API

The extension is still in development so the API is not stabilized yet.

All classes are defined in namespace `Crypto`. Currently there are 3 classes and 1 exception class.

### PHP definition for the classes

The internal code is written in C. The body of the methods is not shown though.

```php
<?php
/**
 * Alorithm class (parent of cipher and digest algorithms)
 */
abstract class Crypto\Algorithm {
    /**
     * Algorithm name
     * @var string
     */
    protected $algorithm;
    
    /**
     * Algorithm class abstract constructor
     * @param string $algorithm
     */
    abstract public function __construct($algorithm);
    
    /**
     * Returns algorithm string
     * @return string
     */
    public function getAlgorithm() {}
    
}

/**
 * Class wrapping cipher algorithms
 */
class Crypto\Cipher extends Crypto\Algorithm {
    /**
     * Finds out whether algorithm exists
     * @param string $algorithm
     * @return bool
     */
    public static function hasAlgorithm($algorithm) {}
    
    /**
     * Initializes cipher encryption
     * @param string $key
     * @param string $iv
     * @return null
     */
    public function encryptInit($key, $iv = null) {}
    
    /**
     * Updates cipher encryption
     * @param string $data
     * @return string
     */
    public function encryptUpdate($data) {}
    
    /**
     * Finalizes cipher encryption
     * @return string
     */
    public function encryptFinal() {}
    
    /**
     * Enrypts text to ciphertext
     * @param string $data
     * @param string $key
     * @param string $iv
     * @return string
     */
    public function encrypt($data, $key, $iv = null) {}
    
    /**
     * Initializes cipher decription
     * @param string $key
     * @param string $iv
     * @return null
     */
    public function decryptInit($key, $iv = null) {}
    
    /**
     * Updates cipher decryption
     * @param string $data
     * @return string
     */
    public function decryptUpdate($data) {}
    
    /**
     * Finalizes cipher decryption
     * @return string
     */
    public function decryptFinal() {}
    
    /**
     * Decrypts ciphertext to decrypted text
     * @param string $data
     * @param string $key
     * @param string $iv
     * @return string
     */
    public function decrypt($data, $key, $iv = null) {}
    
    /**
     * Returns cipher block size
     * @return int
     */
    public function getBlockSize() {}
    
    /**
     * Returns cipher key length
     * @return int
     */
    public function getKeyLength() {}
    
    /**
     * Returns cipher IV length
     * @return int
     */
    public function getIVLength() {}
    
}

/**
 * Class wrapping digest algorithms
 */
class Crypto\Digest extends Crypto\Algorithm {
    /**
     * Finds out whether algorithm exists
     * @param string $algorithm
     * @return bool
     */
    public static function hasAlgorithm($algorithm) {}
    
    /**
     * Initializes digest
     * @return null
     */
    public function init() {}
    
    /**
     * Updates digest
     * @param string $data
     * @return null
     */
    public function update($data) {}
    
    /**
     * Finalizes digest
     * @return string
     */
    public function final() {}
    
    /**
     * Makes digest
     * @param string $data
     * @return string
     */
    public function make($data) {}
    
    /**
     * Returns digest block size
     * @return int
     */
    public function getBlockSize() {}
    
    /**
     * Returns digest size
     * @return int
     */
    public function getSize() {}
    
}

/**
 * Exception class for algorithms errors
 */
class Crypto\AlgorithmException extends Exception {
    const CIPHER_NOT_FOUND = 1;
    const CIPHER_KEY_LENGTH = 2;
    const CIPHER_IV_LENGTH = 3;
    const CIPHER_INIT_FAILED = 4;
    const CIPHER_UPDATE_FAILED = 5;
    const CIPHER_FINAL_FAILED = 6;
    const ENCRYPT_INIT_STATUS = 7;
    const ENCRYPT_UPDATE_STATUS = 8;
    const ENCRYPT_FINAL_STATUS = 9;
    const DECRYPT_INIT_STATUS = 10;
    const DECRYPT_UPDATE_STATUS = 11;
    const DECRYPT_FINAL_STATUS = 12;
    const DIGEST_NOT_FOUND = 13;
    const DIGEST_INIT_FAILED = 14;
    const DIGEST_UPDATE_FAILED = 15;
    const DIGEST_FINAL_FAILED = 16;
    const DIGEST_UPDATE_STATUS = 17;
    const DIGEST_FINAL_STATUS = 18;
    
}
```

## Examples

### Cipher example

Cipher class is for cipher encryption and decryption of the text. The following example shows usage of the Cipher API.

```php
<?php
namespace Crypto;

$algorithm = 'aes-256-cbc';

if (!Cipher::hasAlgorithm($algorithm)) {
	die("Algorithm $algorithm not found" . PHP_EOL);
}

try {
	$cipher = new Cipher($algorithm);

	// Algorithm method for retrieving algorithm
	echo "Algorithm: " . $cipher->getAlgorithm() . PHP_EOL;

	// Params
	$key_len = $cipher->getKeyLength();
	$iv_len = $cipher->getIVLength();
	
	echo "Key length: " . $key_len . PHP_EOL;
	echo "IV length: "  . $iv_len . PHP_EOL;
	echo "Block size: " . $cipher->getBlockSize() . PHP_EOL;

	// This is just for this example. You shoul never use such key and IV!
	$key = str_repeat('x', $key_len);
	$iv = str_repeat('i', $iv_len);

	// Test data
	$data1 = "Test";
	$data2 = "Data";
	$data = $data1 . $data2;

	// Simple encryption
	$sim_ct = $cipher->encrypt($data, $key, $iv);
	
	// init/update/final encryption
	$cipher->encryptInit($key, $iv);
	$iuf_ct  = $cipher->encryptUpdate($data1);
	$iuf_ct .= $cipher->encryptUpdate($data2);
	$iuf_ct .= $cipher->encryptFinal();

	// Raw data output (used base64 format for printing)
	echo "Ciphertext (sim): " . base64_encode($sim_ct) . PHP_EOL;
	echo "Ciphertext (iuf): " . base64_encode($iuf_ct) . PHP_EOL;
	// $iuf_out == $sim_out
	$ct = $sim_ct;
	
	// Simple decryption
	$sim_text = $cipher->decrypt($ct, $key, $iv);
	
	// init/update/final decryption
	$cipher->decryptInit($key, $iv);
	$iuf_text = $cipher->decryptUpdate($ct);
	$iuf_text .= $cipher->decryptFinal();

	// Raw data output ($iuf_out == $sim_out)
	echo "Text (sim): " . $sim_text . PHP_EOL;
	echo "Text (iuf): " . $iuf_text . PHP_EOL;
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}
```

Digest class is for creating message digest. The following example shows usage of the Digest API.

```php
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
```

## TODO list

You can find my TODO list [here](https://github.com/bukka/php-crypto/blob/master/TODO.md).

# PHP OpenSSL Crypto wrapper

The php-crypto is an objective wrapper for OpenSSL Crypto library.


## Installation

### Linux

Before starting with installation this extensions, the `OpenSSL` library has to be installed. It is defaultly installed on the most Linux distribution.

Currently PHP needs to be compiled with OpenSSL extension (`--with-openssl`). This dependency will be removed in the future.

#### Fedora

The RPM package for PHP Crypto is available in Remi's repository: http://rpms.famillecollet.com/

It is available for Fedora, RHEL and clones (CentOS, SC and others).

After downloading remi-release RPM, the package can be installed by executing following command:
```
$ sudo yum --enablerepo=remi install php-pecl-crypto
```

#### PECL

This extension is available on PECL. The package is not currently stable. If the config `preferre_state` is stable, then the version needs to be specified.

```
$ sudo pecl install crypto-0.x.y
```

where `x` is an installed minor version number and `y` bug fixing version number.


#### Manual Installation

It's important to have a git installed as it's necessary for recursive fetch of [phpc](https://github.com/bukka/phpc).

First clone recursively the repository
```
git clone --recursive https://github.com/bukka/php-crypto.git
```

Then go to the created directory and compile the extension. The PHP development package has to be installed (command `phpize` must be available).
```
cd php-crypto
phpize
./configure
make
sudo make install
```

Finally the following line needs to be added to `php.ini`
```
extension=crypto.so
```

Be aware that master branch contains a slightly different error handling. You can see examples for more details. All changes will be soon documented on wiki.

### Windows

Precompiled binary `dll` libraries for php-crypto are available on [the PECL crypto page](http://pecl.php.net/package/crypto).

The php-crypto `dll` is also available in Jan-E Windows builds on [Apache Lounge](https://www.apachelounge.com/viewforum.php?f=6).


## API

The extension is still in development so the API is not stabilized yet.

All classes are defined in namespace `Crypto`.

### PHP definition for the classes

The internal code is written in C so the body of methods is not shown.

```php
<?php
/**
 * Class providing cipher algorithms
 */
class Crypto\Cipher {
    const MODE_ECB = 1;
    const MODE_CBC = 2;
    const MODE_CFB = 3;
    const MODE_OFB = 4;
    const MODE_CTR = 5;
    const MODE_GCM = 6;
    const MODE_CCM = 7;
    const MODE_XTS = 65537;
    
    /**
     * Returns cipher algorithms
     * @param bool $aliases
     * @param string $prefix
     * @return string
     */
    public static function getAlgorithms($aliases = false, $prefix = null) {}
    
    /**
     * Finds out whether algorithm exists
     * @param string $algorithm
     * @return bool
     */
    public static function hasAlgorithm($algorithm) {}
    
    /**
     * Finds out whether the cipher mode is defined in the used OpenSSL library
     * @param int $mode
     * @return bool
     */
    public static function hasMode($mode) {}
    
    /**
     * Cipher magic method for calling static methods
     * @param string $name
     * @param array $arguments
     */
    public static function __callStatic($name, $arguments) {}
    
    /**
     * Cipher constructor
     * @param string $algorithm
     * @param int $mode
     * @param string $key_size
     */
    public function __construct($algorithm, $mode = NULL, $key_size = NULL) {}
    
    /**
     * Returns cipher algorithm name
     * @return string
     */
    public function getAlgorithmName() {}
    
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
    public function encryptFinish() {}
    
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
    public function decryptFinish() {}
    
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
    
    /**
     * Returns cipher mode
     * @return int
     */
    public function getMode() {}
    
    /**
     * Returns authentication tag
     * @param int $tag_size
     * @return string
     */
    public function getTag($tag_size) {}
    
    /**
     * Sets authentication tag
     * @param string $tag
     * @return null
     */
    public function setTag($tag) {}
    
    /**
     * Sets additional application data for authenticated encryption
     * @param string $aad
     * @return null
     */
    public function setAAD($aad) {}
    
}

/**
 * Class providing hash algorithms
 */
class Crypto\Hash {
    /**
     * Returns hash algorithms
     * @param bool $aliases
     * @param string $prefix
     * @return string
     */
    public static function getAlgorithms($aliases = false, $prefix = null) {}
    
    /**
     * Finds out whether algorithm exists
     * @param string $algorithm
     * @return bool
     */
    public static function hasAlgorithm($algorithm) {}
    
    /**
     * Hash magic method for calling static methods
     * @param string $name
     * @param array $arguments
     */
    public static function __callStatic($name, $arguments) {}
    
    /**
     * Hash constructor
     * @param string $algorithm
     */
    public function __construct($algorithm) {}
    
    /**
     * Returns hash algorithm name
     * @return string
     */
    public function getAlgorithmName() {}
    
    /**
     * Updates hash
     * @param string $data
     * @return null
     */
    public function update($data) {}
    
    /**
     * Return hash digest in raw foramt
     * @return string
     */
    public function digest() {}
    
    /**
     * Return hash digest in hex format
     * @return string
     */
    public function hexdigest() {}
    
    /**
     * Returns hash block size
     * @return int
     */
    public function getBlockSize() {}
    
    /**
     * Returns hash size
     * @return int
     */
    public function getSize() {}
    
}

/**
 * Class for base64 encoding and docoding
 */
class Crypto\Base64 {
    /**
     * Encodes string $data to base64 encoding
     * @param string $data
     * @return string
     */
    public function encode($data) {}
    
    /**
     * Decodes base64 string $data to raw encoding
     * @param string $data
     * @return string
     */
    public function decode($data) {}
    
    /**
     * Base64 constructor
     */
    public function __construct() {}
    
    /**
     * Encodes block of characters from $data and saves the reminder of the last block to the encoding context
     * @param string $data
     */
    public function encode($data) {}
    
    /**
     * Encodes characters that left in the encoding context
     */
    public function encodeFinish() {}
    
    /**
     * Decodes block of characters from $data and saves the reminder of the last block to the encoding context
     * @param string $data
     */
    public function decode($data) {}
    
    /**
     * Decodes characters that left in the encoding context
     */
    public function decodeFinish() {}
    
}

/**
 * Exception class for base64 errors
 */
class Crypto\Base64Exception extends Exception {
    const ENCODE_UPDATE_STATUS = 1;
    const ENCODE_FINISH_STATUS = 2;
    const DECODE_UPDATE_STATUS = 3;
    const DECODE_FINISH_STATUS = 4;
    const DECODE_FAILED = 5;
    
}

/**
 * Class for generating random numbers
 */
class Crypto\Rand {
    /**
     * Generates pseudo random bytes
     * @param int $num
     * @param bool $must_be_strong
     * @param bool $returned_strong_result
     * @return string
     */
    public static function generate($num, $must_be_strong = true, &$returned_strong_result = true) {}
    
    /**
     * Mixes bytes in $buf into PRNG state
     * @param string $buf
     * @param float $entropy
     * @return null
     */
    public static function seed($buf, $entropy = (float) strlen($buf)) {}
    
    /**
     * Cleans up PRNG state
     * @return null
     */
    public static function cleanup() {}
    
    /**
     * Reads a number of bytes from file $filename and adds them to the PRNG. If max_bytes is non-negative, up to to max_bytes are read; if $max_bytes is -1, the complete file is read
     * @param string $filename
     * @param int $max_bytes
     * @return int
     */
    public static function loadFile($filename, $max_bytes = -1) {}
    
    /**
     * Writes a number of random bytes (currently 1024) to file $filename which can be used to initialize the PRNG by calling Crypto\Rand::loadFile() in a later session
     * @param string $filename
     * @return int
     */
    public static function writeFile($filename) {}
    
    /**
     * Queries the entropy gathering daemon EGD on socket path. It queries $bytes bytes and if $seed is true, then the data are seeded, otherwise the data are returned
     * @param string $path
     * @param int $bytes
     * @param bool $seed
     * @return mixed
     */
    public static function egd($path, $bytes = 255, $seed = true) {}
    
}
```

## Examples

The examples can be found in [the example directory](examples).


## TODO list

The TODO list can be found [here](TODO.md).


## History

The release history can be found [here](HISTORY.md).

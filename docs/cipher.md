## Cipher

The `Cipher` class handles all encryption and decription including AEAD 
as well as provides various information about selecte cipher algorithm.

### Constants

#### `Cipher::MODE_CBC`

The CBC (Cipher Block Chaining) mode XOR's the previous block with the
currently en/decrypted one. It requires random IV to be set.

#### `Cipher::MODE_CCM`

The CCM (Counter with CBC-MAC) is an authenticated mode. It requires
a length pre-initialization which means that a plain resp. cipher
text must be known before encryption resp. decription. That makes
it unsituable for streams or continuous cipher update.

Encryption is done using CTR (Counter) mode which means that
a supplied nonce and counter is used. The nonce is passed as an IV.
The default tag size is 16 bytes.

#### `Cipher::MODE_CFB`

The CFB (Cipher FeedBack) mode makes a block ciphper into
a self-synchronizing stream cipher.

#### `Cipher::MODE_CTR`

The CTR (CounTeR) mode uses counter and a random nonce.

#### `Cipher::MODE_ECB`

The ECB (Electronic Codebook) mode is an insecure mode susceptible
on replay attack if a message length is greater than a block length.

#### `Cipher::MODE_GCM`

The GCM (Golias Counter Mode) is an authenticated mode.

#### `Cipher::MODE_OFB`

The OFB (Output FeedBack) mode makes a block cipher into 
a synchronous stream cipher

#### `Cipher::MODE_XTS`

The XTS (XEX-based tweaked codebook mode with ciphertext stealing) mode
is a mode designed for hard disk storage.


### Static Methods

#### `Cipher::__callStatic($name, $arguments)`

_**Description**_: Creates a cipher using a static call syntax.

The usage of `__callStatic` magic method allows simplified syntax for creating
a `Cipher` object (e.g. `Cipher::aes(Crypto\Cipher::MODE_CBC, 128)`). The `$name`
depicts the algorithm which is checked if it's found. If not then `CipherException`
is thrown. Otherwise the new `Cipher` instance is returned.

##### *Parameters*

*name* : `string` - the algorithm name (e.g. `aes`)

*arguments* : `array` - there should be an algorithm mode
and key size (if supported by algorithm)

##### *Return value*

`Cipher`: New instances of the class.

##### *Throws*

It can throw `CipherException` with code

- `CipherException::ALGORITHM_NOT_FOUND` - the algorithm (name) is not found

##### *Examples*

```php
$cipher = \Crypto\Cipher::aes(\Crypto\Cipher::MODE_CBC, 128);
```

#### `Cipher::getAlgorithms($aliases = false, $prefix = null)`

_**Description**_: Returns all cipher algorithms.

This static method returns all cipher algorithms. Their parameters
allow filtering of the result. Some algorithms have aliases that
can be returned if the `$aliases` parameter is `true`. The `$prefix`
allows filtering by the supplied prefix string.

##### *Parameters*

*aliases* : `bool` - whether to show aliases
*prefix* : `string` - prefix that is used for filtering of the result

##### *Throws*

This method does not throw any exception.

##### *Return value*

`array`: list of supported cipher alorithms

##### *Examples*

```php
print_r(\Crypto\Cipher::getAlgorithms());
```

#### `Cipher::hasAlgorithm($algorithm)`

_**Description**_: Finds out wheter the supplied algorithm is supported

This static method checks if the supplied cipher algorithm is supported.

##### *Parameters*

*algorithm* : `string` - algorithm name

##### *Throws*

This method does not throw any exception.

##### *Return value*

`bool`: if the algorithm is supperted, returns `true`, otherwise `false`

##### *Examples*

```php
if (\Crypto\Cipher::hasAlgorithm('aes-128-ccm')) {
    // use AES wiht CCM mode
}
```

#### `Cipher::hasMode($mode)`

_**Description**_: Finds out wheter the supplied mode is supported

This static method checks if the supplied cipher mode is supported.
The `$mode` parameter must be one of the mode cipher constant
defined in `Cipher` class.

##### *Parameters*

*mode* : `int` - mode constant

##### *Throws*

This method does not throw any exception.

##### *Return value*

`bool`: if the mode is supperted, returns `true`, otherwise `false`

##### *Examples*

```php
if (\Crypto\Cipher::hasMode(\Crypto\Cipher::MODE_CCM)) {
    // use CCM mode
}
```

### Instance Methods

#### `Cipher::__construct($algorithm)`

#### `Cipher::decrypt($data, $key, $iv = null)()`

#### `Cipher::decryptFinish()`

#### `Cipher::decryptInit($key, $iv = null)`

#### `Cipher::decryptUpdate($data) `

#### `Cipher::encrypt($data, $key, $iv = null)`

#### `Cipher::encryptFinish()`

#### `Cipher::encryptInit($key, $iv = null)`

#### `Cipher::encryptUpdate($data)`

#### `Cipher::getAlgorithmName()`

#### `Cipher::getBlockSize()`

#### `Cipher::getIVLength()`

#### `Cipher::getKeyLength()`

#### `Cipher::getMode()`

#### `Cipher::getTag($tag_size)`

#### `Cipher::setAAD($aad)`

#### `Cipher::setTag($tag)`

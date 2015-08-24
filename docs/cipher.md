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

#### `Cipher::__construct($algorithm, $mode = NULL, $key_size = NULL)`

_**Description**_: Creates a new cipher object

The constructor allows creating an object using two ways. Either algorithm
name is a string containing all details (algorithm, mode, key size) or
it is just a name of the block algorithm (e.g. AES) followed by mode
`Cipher` class constant and, if algorithm allows that, then key size.
Internally the name is concatened to the first form so the result is
the same. The final algorithm name is then checked if it is supported.
If not, then the `CipherException` is thrown.

##### *Parameters*

*algorithm* : `string` - algorithm name

*mode* : `int` - mode constant

*key_size* : `int` - algorithm key size

##### *Throws*

It can throw `CipherException` with code

- `CipherException::ALGORITHM_NOT_FOUND` - the algorithm (name) is not found

##### *Return value*

`Cipher`: new cipher object

##### *Examples*

Creating cipher using just algorithm parameter
```php
$cipher = new \Crypto\Cipher('AES-128-GCM');
```

Creating cipher using composed parameters
```php
use Crypto\Cipher;

$cipher = new Cipher('AES', Cipher::MODE_GCM, 128);
```

#### `Cipher::decrypt($data, $key, $iv = null)`

_**Description**_: Decrypts encrypted data using key and IV

This method decrypts encrypted data (cipher text) on the `Cipher`
object. It uses a supplied key `$key` and an initial vector `$iv`
for decryption. Internally it calls init, update and finish
operations on cipher context. If any of them fails, a `CipherException`
with an appropriate code is thrown.

The key resp. IV parameters has to contain an exact number of bytes
that is returned by `Cipher::getKeyLength` resp. `Cipher::getIVLength()`.
If it's not the case, then a `CipherException` is thrown.

##### *Parameters*

*data* : `string` - cipher text

*key* : `string` - key

*iv* : `string` - initial vector

##### *Throws*

It can throw `CipherException` with code

- `CipherException::INIT_ALG_FAILED` - initialization of cipher algorithm failed
- `CipherException::INIT_CTX_FAILED` - initialization of cipher context failed
- `CipherException::UPDATE_FAILED` - updating of decription failed
- `CipherException::FINISH_FAILED` - finalizing of decription failed
- `CipherException::INPUT_DATA_LENGTH_HIGH` - if the data length exceed C INT_MAX
- `CipherException::KEY_LENGTH_INVALID` - the key length is invalid
- `CipherException::IV_LENGTH_INVALID` - the IV length is invalid

##### *Return value*

`string`: The decrypted plain text.

##### *Examples*

```php
$cipher = new \Crypto\Cipher('AES-128-GCM');
echo $cipher->decrypt($msg, $key, $iv);
```

#### `Cipher::decryptFinish()`

_**Description**_: Finalizes a decription

This method decrypts the outstanding incomplete block if there is
any such block in cipher context. It also closes the context so
the update cannot be called again unless the object is again
initialized. In addition it finishes the authentication for GCM mode.

If the operation fails (e.g. verification fails), then
`CipherException` is thrown. The same exception with different code
is thrown if the context has not been initialized for decryption
before.

##### *Parameters*

This method has no parameters.

##### *Throws*

It can throw `CipherException` with code

- `CipherException::FINISH_FAILED` - finalizing of decription failed
- `CipherException::FINISH_DECRYPT_FORBIDDEN` - cipher has not been initialized for decryption

##### *Return value*

`string`: The decrypted plain text from the last incomplete block or empty string.

##### *Examples*

```php
$cipher = new \Crypto\Cipher('AES-128-CTR');
$cipher->descryptInit($key, $iv);
$ct = $cipher->decryptUpdate($msg);
$ct .= $cipher->decryptFinish();
```

#### `Cipher::decryptInit($key, $iv = null)`

_**Description**_: Initializes cipher decription

This method initializes decription on the `Cipher` object.
It uses a supplied key `$key` and an initial vector `$iv`. If
the initialization fails, a `CipherException` with an appropriate
code is thrown.

The key resp. IV parameters has to contain an exact number of bytes
that is returned by `Cipher::getKeyLength` resp. `Cipher::getIVLength()`.
If it's not the case, then a `CipherException` is thrown.

##### *Parameters*

*key* : `string` - key

*iv* : `string` - initial vector

##### *Throws*

It can throw `CipherException` with code

- `CipherException::INIT_ALG_FAILED` - initialization of cipher algorithm failed
- `CipherException::INIT_CTX_FAILED` - initialization of cipher context failed
- `CipherException::KEY_LENGTH_INVALID` - the key length is invalid
- `CipherException::IV_LENGTH_INVALID` - the IV length is invalid

##### *Return value*

`null`: Nothing is returned.

##### *Examples*

```php
$cipher = new \Crypto\Cipher('AES-128-CBC');
try {
    $cipher->descryptInit($key, $iv);
} catch (\Crypto\CipherException $ex) {
    switch ($ex->getCode()) {
        case \Crypto\CipherException::KEY_LENGTH_INVALID:
            echo "You need to set a correct key length";
            break;
        case \Crypto\CipherException::IV_LENGTH_INVALID:
            echo "You need to set a correct IV length";
            break;
        default:
            echo $ex->getMessage();
            break;
    }
}
```

#### `Cipher::decryptUpdate($data) `

_**Description**_: Updates decription context with data and returns encrypted blocks.

This method decrypts encrypted data (cipher text) on the `Cipher` object.
It updates an initialized context and all encrypted blocks are returned. If it is
not initialized, the a `CipherException` is thrown.

If the decription fails, a `CipherException` is thrown.

##### *Parameters*

*data* : `string` - cipher text

##### *Throws*

It can throw `CipherException` with code

- `CipherException::UPDATE_FAILED` - updating of decription failed
- `CipherException::INPUT_DATA_LENGTH_HIGH` - if the data length exceed C INT_MAX
- `CipherException::UPDATE_DECRYPT_FORBIDDEN` - cipher has not been initialized for decryption

##### *Return value*

`string`: The decrypted plain text.

##### *Examples*

```php
$cipher = new \Crypto\Cipher('AES-128-CTR');
$cipher->descryptInit($key, $iv);
$ct = "";
while (($data = read_data_from_somewhere()) !== false) {
    $ct .= $cipher->decryptUpdate($msg);
}
$ct .= $cipher->decryptFinish();
```

#### `Cipher::encrypt($data, $key, $iv = null)`

_**Description**_: Encrypts data using key and IV

This method encrypts data (plain text) on the `Cipher`
object. It uses a supplied key `$key` and an initial vector `$iv`
for encryption. Internally it calls init, update and finish
operations on cipher context. If any of them fails, a `CipherException`
with an appropriate code is thrown.

The key resp. IV parameters has to contain an exact number of bytes
that is returned by `Cipher::getKeyLength` resp. `Cipher::getIVLength()`.
If it's not the case, then a `CipherException` is thrown.

##### *Parameters*

*data* : `string` - plain text

*key* : `string` - key

*iv* : `string` - initial vector

##### *Throws*

It can throw `CipherException` with code

- `CipherException::INIT_ALG_FAILED` - initialization of cipher algorithm failed
- `CipherException::INIT_CTX_FAILED` - initialization of cipher context failed
- `CipherException::UPDATE_FAILED` - updating of encription failed
- `CipherException::FINISH_FAILED` - finalizing of encription failed
- `CipherException::INPUT_DATA_LENGTH_HIGH` - if the data length exceed C INT_MAX
- `CipherException::KEY_LENGTH_INVALID` - the key length is invalid
- `CipherException::IV_LENGTH_INVALID` - the IV length is invalid

##### *Return value*

`string`: The encrypted cipher text.

##### *Examples*

```php
$cipher = new \Crypto\Cipher('AES-128-CTR');
echo $cipher->encrypt($cipher_text, $key, $iv);
```


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

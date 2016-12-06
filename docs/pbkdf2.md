## PBKDF2

The `PBKDF2` class provides functions for creating a password based key derivation
function 2 using multiple iteration of `HMAC`.

The `PBKDF2` class extends [`KDF`](kdf.md) class. It means that it inherits methods
for setting / getting length and salt.

### Instance Methods

#### `PBKDF2::__construct($hashAlgorithm, $length, $salt = NULL, $iter = 1000)`

_**Description**_: Creates a new `PBKDF2` class if supplied algorithm is supported.

The constructor first checks if the `hashAlgorithm` is found. If not, then
`PBKDF2Exception` is thrown. Otherwise a new instance of `PBKDF2` with the supplied
length, salt and number of iterations is created.

##### *Parameters*

*hashAlgorithm* : `string` - the algorithm name (e.g. `sha1`, `sha256`)
*length* : `int` - the key length
*salt* : `string` - the salt
*iter* : `int` - the number of iterations

##### *Return value*

`PBKDF2`: New instances of the `PBKDF2` class.

##### *Throws*

It can throw `KDFException` with code

- `KDFException::KEY_LENGTH_LOW` - the supplied key length is too low
- `KDFException::KEY_LENGTH_HIGH` - the supplied key length is too high
- `KDFException::SALT_LENGTH_HIGH` - if the data length exceeds
C INT_MAX
- `PBKDF2Exception::HASH_ALGORITHM_NOT_FOUND` - the supplied has algorithm
is invalid
- `PBKDF2Exception::ITERATIONS_HIGH` - the supplied iterations count is too high

##### *Examples*

```php
$pbkdf2 = new \Crypto\PBKDF2('sha256', 32, \Crypto\Rand::generate(16));
```

If the hash algorithm is passed by user in variable, then it might be a good idea to
wrap it in a try/catch block:
```php
try {
    $pbkdf2 = new \Crypto\PBKDF2($key, $hash_algorithm, \Crypto\Rand::generate(16));
}
catch (\Crypto\KDFException $e) {
    echo $e->getMessage();
}
```

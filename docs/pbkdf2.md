## PBKDF2

The `PBKDF2` class provides functions for creating a password based key derivation
function 2 using multiple iteration of `HMAC`.

The `PBKDF2` class extends [`KDF`](kdf.md) class. It means that it inherits methods
for derivation and setting / getting length and salt. All these methods are
documented in [`KDF`](kdf.md).

### Instance Methods

#### `PBKDF2::__construct($hashAlgorithm, $length, $salt = NULL, $iterations = 1000)`

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
- `PBKDF2Exception::HASH_ALGORITHM_NOT_FOUND` - the supplied hash algorithm
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

#### `PBKDF2::getHashAlgorithm()`

_**Description**_: Returns hash algorithm name.

This method returns a hash algorithm name. The algorithm will be used
for HMAC when deriving a key using `PBKDF2::derive`.

The name is usually in upper case even if it was supplied as lower case.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`string`: The hash algorithm.

##### *Examples*

```php
$pbkdf2 = new \Crypto\PBKDF2('sha256', 32, \Crypto\Rand::generate(16));
// this will output SHA256
echo $pbkdf2->getHashAlgorithm();
```

#### `PBKDF2::getIterations()`

_**Description**_: Returns the number of iterations.

This method returns the number of iterations for deriving key.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: The number of iterations.

##### *Examples*

```php
$pbkdf2 = new \Crypto\PBKDF2('sha256', 32, \Crypto\Rand::generate(16), 1200);
// returns 1200
echo $pbkdf2->getIterations();
```

#### `PBKDF2::setHashAlgorithm($hashAlgorithm)`

_**Description**_: Sets hash algorithm name.

This method sets a hash algorithm by its name. It will be then used
by HMAC when deriving key using `PBKDF2::derive`.

##### *Parameters*

*hashAlgorithm* : `string` - the hash algorithm name

##### *Throws*

It can throw `PBKDF2Exception` with code

- `PBKDF2Exception::HASH_ALGORITHM_NOT_FOUND` - the supplied hash algorithm
is invalid

##### *Return value*

`bool`: true if the hash algorithm was set succesfully

##### *Examples*

```php
$pbkdf2 = new \Crypto\PBKDF2('sha256', 32, \Crypto\Rand::generate(16));
// if we want to change hash algorithm to SHA512
$pbkdf2->setHashAlgorithm('sha512');
```

#### `PBKDF2::setIterations($iterations)`

_**Description**_: Sets the number of iterations.

This method sets the number of iterations for key derivation which will be
used in `PBKDF2::derive`. Any number less than 1 is treated as a single
iteration.

##### *Parameters*

*iterations* : `int` - the number of iterations

##### *Throws*

It can throw `PBKDF2Exception` with code

- `PBKDF2Exception::ITERATIONS_HIGH` - the supplied iterations count is too high

##### *Return value*

`bool`: true if the number of iterations was set succesfully

##### *Examples*

```php
$pbkdf2 = new \Crypto\PBKDF2('sha256', 32, \Crypto\Rand::generate(16), 1200);
// if we want to change number of iterations to 1000
$pbkdf2->setIterations(1000);
```

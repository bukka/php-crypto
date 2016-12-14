## HMAC

The `HMAC` class provides functions for creating a keyed-hash message
authentication code (HMAC) message digest from a supplied key and
block of data. It allows to choose a message digest algorithm.

The `HMAC` class extends `MAC` class which extends [`Hash`](hash.md) class. It
means that with an exception of the constructor all methods are inherited
from [`Hash`](hash.md) class.

### Instance Methods

#### `HMAC::__construct($key, $algorithm)`

_**Description**_: Creates a new `HMAC` class if supplied algorithm is supported.

The constructor first checks if the algorithm is found. If not, then
`MACException` is thrown. Otherwise a new instance of `HMAC` is created.

The key length is compared with block size:
- if the key length is the same as block size, then the key is used as it is
- if the key length is smaller, then the key is padded with zero bytes to the block size
- if the key length is greater, then the key is hashed (unless it's greater than C `INT_MAX`)
- if the key length is greater then C `INT_MAX`, then the exception is thrown

##### *Parameters*

*key* : `string` - the key string
*algorithm* : `string` - the algorithm name (e.g. `sha256`, `sha512`, `md5`)

##### *Return value*

`HMAC`: New instances of the `HMAC` class.

##### *Throws*

It can throw `MACException` with code

- `MACException::HASH_ALGORITHM_NOT_FOUND` - the supplied algorithm is not found
- `MACException::KEY_LENGTH_INVALID` - the supplied key length is too high (over C INT_MAX)

##### *Examples*

```php
$hmac = new \Crypto\HMAC('key', 'sha256');
```

If the algorithm is passed by user in variable, then it might be a good idea to
wrap it in a try/catch block:
```php
try {
    $hmac = new \Crypto\HMAC($key, $hash_algorithm);
}
catch (\Crypto\HashException $e) {
    echo $e->getMessage();
}
```

#### `HMAC::digest()`

_**Description**_: Returns a MAC in binary encoding

This method returns a binary message authentication code (MAC). 
It also finalizes the HMAC context which means that if 
`HMAC::update` is called again, then the context is 
reinitialized - the result is the same like creating a new object 
using the same algorithm and key and then calling `HMAC::update`.

If the `HMAC` object has not been updated, then the result will
be a HMAC for an empty string.

##### *Parameters*

This method has no parameters.

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::DEGEST_FAIED` - creating digest failed

##### *Return value*

`string`: The MAC binary string with length equal to
the result of `HMAC::getSize()`

##### *Examples*

```php
$hmac = new \Crypto\HMAC('key', 'sha256');
$digest = $hmac->update('abc')->digest();
```

#### `HMAC::getAlgorithmName()`

_**Description**_: Returns an underlaying hash algorithm name.

It is a getter for internal inherited `Hash::$algorithm` 
reod only property which is set during the object construction.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`string`: The name of the underlaying hash algorithm (e.g. `sha256`)

##### *Examples*

```php
$hmac = new \Crypto\HMAC('key', 'sha256');
// this will output SHA256
echo $hmac->getAlgorithmName();
```

#### `HMAC::getBlockSize()`

_**Description**_: Returns an underlaying hash block size in bytes.

This method returns a block size of the underlaying hash algorithm. 
That should not be confused with the output size (which is returned by
`HMAC::getSize()`). The block size is a size that the hash algorithm
operates on and it is bigger than output size (e.g. 64 bytes which is 
512 bits for SHA256).

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: underlaying hash block size in bytes

##### *Examples*

```php
$hmac = new \Crypto\HMAC('key', 'sha256');
// this will output 64
echo $hmac->getBlockSize();
```

#### `HMAC::getSize()`

_**Description**_: Returns an underlaying hash output size in bytes.

This method returns the output size of the underlaying hash algorithm. It means
how many bytes will be returned by the `HMAC::digest()` method.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: underlaying hash output size in bytes

##### *Examples*

```php
$hash = new \Crypto\HMAC('key', 'sha256');
// this will output 32
echo $hash->getSize();
```

#### `HMAC::hexdigest()`

_**Description**_: Returns a MAC in hex encoding.

This method returns a message authentication code. It also 
finalizes the `HMAC` context which means that if `Hash::update`
is called again, then the context is reinitialized - the result 
is the same like creating a new object using the same algorithm 
and then calling `Hash::update` on it.

If the `HMAC` object has not been updated, then the result will
be a HMAC for an empty string.

##### *Parameters*

This method has no parameters.

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::DEGEST_FAIED` - creating digest failed

##### *Return value*

`string`: message authentication code hex string

##### *Examples*

```php
$hmac = new \Crypto\HMAC('key', 'sha256');
echo $hmac->update('abc')->hexdigest();
```

#### `HMAC::update($data)`

_**Description**_: Updates the HMAC object with supplied data 

This method updates `HMAC` object context with supplied data. It can
be useful when reading data from database or big files.

Before the update, it also initializes the internal context if it's
the first update. If the initialization or update fails, the exception
is thrown.

##### *Parameters*

*data* : `string` - data that updates the HMAC

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::UPDATE_FAIED` - updating HMAC failed

##### *Return value*

`HMAC`: An instance of the called object (for chaining)

##### *Examples*

```php
try {
    $key = 'secret_key';
    $hmac = new \Crypto\HMAC($key, 'sha256');
    while (($data = read_data_from_somewhere()) !== false) {
        $hmac->update($data);
    }
    echo $hmac->hexdigest();
} catch (\Crypto\HashException $e) {
    echo $e->getMessage();
}
```

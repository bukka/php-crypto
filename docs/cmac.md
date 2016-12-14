## CMAC

The `CMAC` class provides functions for creating a block cipher-based message 
authentication code (CMAC). It allows to choose an underlaying block
cipher algorithm.

The `CMAC` class extends `MAC` class which extends [`Hash`](hash.md) class. It
means that with exception of a constructor all methods are inherited
from [`Hash`](hash.md) class.

### Instance Methods

#### `CMAC::__construct($key, $algorithm)`

_**Description**_: Creates a new `CMAC` class if supplied algorithm is supported.

The constructor first checks if the algorithm is found. If not, then
`MACException` is thrown. Otherwise a new instance of `CMAC` is created.

The key length is compared with the underlaying cipher block size if it's
not equal, then `MACException` is thrown.

##### *Parameters*

*key* : `key` - the key string
*algorithm* : `string` - the cipher algorithm name (e.g. `aes-128-cbc`)

##### *Return value*

`CMAC`: New instances of the `CMAC` class.

##### *Throws*

It can throw `MACException` with code

- `MACException::HASH_ALGORITHM_NOT_FOUND` - the supplied algorithm is not found
- `MACException::KEY_LENGTH_INVALID` - the supplied key length is incorrect

##### *Examples*

```php
$cmac = new \Crypto\CMAC('key', 'aes-128-cbc');
```

If the algorithm is passed by user in variable, then it might be a good idea to
wrap it in a try/catch block:
```php
try {
    $cmac = new \Crypto\CMAC($key, $cipher_algorithm);
}
catch (\Crypto\MACException $e) {
    echo $e->getMessage();
}
```

#### `CMAC::digest()`

_**Description**_: Returns a MAC in binary encoding

This method returns a binary message authentication code (MAC). 
It also finalizes the CMAC context which means that if 
`CMAC::update` is called again, then the context is 
reinitialized - the result is the same like creating a new object 
using the same algorithm and key and then calling `CMAC::update`.

If the `CMAC` object has not been updated, then the result will
be a CMAC for an empty string.

##### *Parameters*

This method has no parameters.

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::DEGEST_FAIED` - creating digest failed

##### *Return value*

`string`: The MAC binary string with length equal to
the result of `CMAC::getSize()`

##### *Examples*

```php
$cmac = new \Crypto\CMAC('key', 'aes-128-cbc');
$digest = $cmac->update('abc')->digest();
```

#### `CMAC::getAlgorithmName()`

_**Description**_: Returns an underlaying cipher algorithm name.

It is a getter for internal inherited `Hash::$algorithm` 
reod only property which is set during the object construction.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`string`: The name of the underlaying cipher (e.g. `aes-128-cbc`)

##### *Examples*

```php
$cmac = new \Crypto\CMAC('key', 'aes-128-cbc');
// this will output AES-128-CBC
echo $cmac->getAlgorithmName();
```

#### `CMAC::getBlockSize()`

_**Description**_: Returns an underlaying cipher block size in bytes.

This method returns a block size of the underlaying cipher algorithm. 

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: underlaying cipher block size in bytes

##### *Examples*

```php
$cmac = new \Crypto\CMAC('key', 'aes-128-cbc');
// this will output 16
echo $cmac->getBlockSize();
```

#### `CMAC::getSize()`

_**Description**_: Returns an output size of the MAC in bytes.

This method returns the output size of the message authentication code.
The output size for CMAC is equal to the block size of the underlaying
cipher. It means that it returns the same value as `CMAC::getBlockSize`.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: underlaying hash output size in bytes

##### *Examples*

```php
$hash = new \Crypto\CMAC('key', 'aes-128-cbc');
// this will output 16
echo $hash->getSize();
```

#### `CMAC::hexdigest()`

_**Description**_: Returns a MAC in hex encoding.

This method returns a message authentication code. It also 
finalizes the `CMAC` context which means that if `Hash::update`
is called again, then the context is reinitialized - the result 
is the same like creating a new object using the same algorithm 
and then calling `Hash::update` on it.

If the `CMAC` object has not been updated, then the result will
be a CMAC for an empty string.

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
$cmac = new \Crypto\CMAC('key', 'aes-128-cbc');
echo $cmac->update('abc')->hexdigest();
```

#### `CMAC::update($data)`

_**Description**_: Updates the CMAC object with supplied data 

This method updates `CMAC` object context with supplied data. It can
be useful when reading data from database or big files.

Before the update, it also initializes the internal context if it's
the first update. If the initialization or update fails, the exception
is thrown.

##### *Parameters*

*data* : `string` - data that updates the CMAC

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::UPDATE_FAIED` - updating CMAC failed

##### *Return value*

`CMAC`: An instance of the called object (for chaining)

##### *Examples*

```php
try {
    $key = pack('H*', '2b7e151628aed2a6abf7158809cf4f3c');
    $cmac = new \Crypto\CMAC($key, 'aes-128-cbc');
    while (($data = read_data_from_somewhere()) !== false) {
        $cmac->update($data);
    }
    echo $cmac->hexdigest();
} catch (\Crypto\MACException $e) {
    echo $e->getMessage();
}
```

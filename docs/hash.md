## Hash

The `Hash` class provides functions for creating message digest from a supplied
block of data. It allows to choose an algorithm and contains additional methods
giving more info like it's block size.

### Static Methods

#### `Hash::__callStatic($name, $arguments)`

_**Description**_: Creates hash digest using a static call syntax.

The usage of `__callStatic` magic method allows simplified syntax for creating
a `Hash` object (e.g. `Hash::sha256($message)`). The `$name` depicts the algorithm
which is checked if it's found. If not then `HashException` is thrown. Otherwise
the new `Hash` instance is returned.

##### *Parameters*

*name* : `string` - the algorithm name (e.g. `sha256`, `sha512`, `md5`)
*arguments* : `array` - there can be just one element which is message

##### *Return value*

`Hash`: New instances of the class.

##### *Throws*

It can throw `HashException` with code

- `HashException::HASH_ALGORITHM_NOT_FOUND` - the algorithm (name) is not found

##### *Examples*

```php
echo \Crypto\Hash::sha256('abc')->hexdigest();
```

#### `Hash::getAlgorithms($aliases = false, $prefix = null)`

_**Description**_: Returns all hash algorithms.

This static method returns all hash algorithms. Their parameters
allow filtering of the result. Some algorithms have aliases that
can be returned if the `$aliases` parameter is `true`. The `$prefix`
allows filtering by the supplied prefix string.

##### *Parameters*

*aliases* : `bool` - whether to show aliases
*prefix* : `string` - prefix that is used for filtering of the result

##### *Throws*

This method does not throw any exception.

##### *Return value*

`array`: list of supported hash alorithms

##### *Examples*

```php
print_r(\Crypto\Hash::getAlgorithms());
```

#### `Hash::hasAlgorithm($algorithm)`

_**Description**_: Finds out wheter the supplied algorithm is supported

This static method checks if the supplied hash algorithm is supported.

##### *Parameters*

*algorithm* : `string` - algorithm name

##### *Throws*

This method does not throw any exception.

##### *Return value*

`bool`: if the algorithm is supperted, returns `true`, otherwise `false`

##### *Examples*

```php
if (\Crypto\Hash::hasAlgorithm('sha512')) {
    // use SHA512
}
```


### Instance Methods

#### `Hash::__construct($algorithm)`

_**Description**_: Creates a new `Hash` class if supplied algorithm is supported.

The constructor first checks if the algorithm is found. If not, then
`HashException` is thrown. Otherwise a new instance of `Hash` is created

##### *Parameters*

*algorithm* : `string` - the algorithm name (e.g. `sha256`, `sha512`, `md5`)

##### *Return value*

`Hash`: New instances of the `Hash` class.

##### *Throws*

It can throw `HashException` with code

- `HashException::HASH_ALGORITHM_NOT_FOUND` - the supplied algorithm is not found

##### *Examples*

```php
$hash = new \Crypto\Hash('sha256');
```

If the algorithm is passed by user in variable, then it might be a good idea to
wrap it in a try/catch block:
```php
try {
    $hash = new \Crypto\Hash($hash_algorithm);
}
catch (\Crypto\HashException $e) {
    echo $e->getMessage();
}
```

#### `Hash::digest()`

_**Description**_: Returns a hash digest in binary encoding

This method returns a binary digest. It also finalizes the hash
context which means that if `Hash::update` is called again,
then the context is reinitialized - the result is the same
like creating a new object using the same algorithm and then
calling `Hash::update` on that object.

If the `Hash` object has not been updated, then the result will
be a hash for an empty string.

##### *Parameters*

This method has no parameters.

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::DEGEST_FAIED` - creating digest failed

##### *Return value*

`string`: The hash binary string with length equal to
the result of `Hash::getSize()`

##### *Examples*

```php
$digest = \Crypto\Hash::sha256('abc')->digest();
```

#### `Hash::getAlgorithmName()`

_**Description**_: Returns a hash algorithm name.

It is a getter for internal `Hash::$algorithm` read only property
which is set during the object creation.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`string`: The name of the hash algorithm (e.g. `sha256`)

##### *Examples*

```php
$hash = new \Crypto\Hash('sha256');
// this will output SHA256
echo $hash->getAlgorithmName();
```

#### `Hash::getBlockSize()`

_**Description**_: Returns a hash block size in bytes.

This method returns the block size of the used hash algorithm. That
should not be confused with the output size (which is returned by
`Hash::getSize()`). The block size is a size that the hash algorithm
operates on and is bigger than output size (e.g. 64 bytes which is 
512 bits for SHA256).

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: hash block size in bytes

##### *Examples*

```php
$hash = new \Crypto\Hash('sha256');
// this will output 64
echo $hash->getBlockSize();
```

#### `Hash::getSize()`

_**Description**_: Returns a hash output size in bytes.

This method returns the output size of the used hash algorithm. It means
how many bytes will be returned by the `Hash::digest()` method.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: hash output size in bytes

##### *Examples*

```php
$hash = new \Crypto\Hash('sha256');
// this will output 32
echo $hash->getSize();
```

#### `Hash::hexdigest()`

_**Description**_: Returns a hash digest in hex encoding

This method returns a hex digest. It also finalizes the hash
context which means that if `Hash::update` is called again,
then the context is reinitialized - the result is the same
like creating a new object using the same algorithm and then
calling `Hash::update` on it.

If the `Hash` object has not been updated, then the result will
be a hash for an empty string.

##### *Parameters*

This method has no parameters.

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::DEGEST_FAIED` - creating digest failed

##### *Return value*

`string`: hash digest hex string

##### *Examples*

```php
echo \Crypto\Hash::sha256('abc')->hexdigest();
```

#### `Hash::update($data)`

_**Description**_: Updates the hash object with supplied data 

This method updates `Hash` object context with supplied data. It can
be useful when reading data from database or big files.

Before the update, it also initializes the internal context if it's
the first update. If the initialization or update fails, the exception
is thrown.

##### *Parameters*

*data* : `string` - data that updates the hash

##### *Throws*

It can throw `HashException` with code

- `HashException::INIT_FAIED` - initialization failed
- `HashException::UPDATE_FAIED` - updating digest failed

##### *Return value*

`Hash`: An instance of the called object (for chaining)

##### *Examples*

```php
try {
    $hash = new \Crypto\Hash('sha256');
    while (($data = read_data_from_somewhere()) !== false) {
        $hash->update($data);
    }
    echo $hash->hexdigest();
} catch (\Crypto\HashException $e) {
    echo $e->getMessage();
}
```

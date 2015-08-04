# PHP OpenSSL Crypto wrapper

The php-crypto is an objective wrapper for OpenSSL Crypto library.


## Installation

### Linux

Before starting with installation this extensions, the `OpenSSL` library
has to be installed. It is defaultly installed on the most Linux distribution.

Currently PHP needs to be compiled with OpenSSL extension (`--with-openssl`).
This dependency will be removed in the future.

#### Fedora

The RPM package for PHP Crypto is available in Remi's repository:
http://rpms.famillecollet.com/

It is available for Fedora, RHEL and clones (CentOS, SC and others).

After downloading remi-release RPM, the package can be installed
by executing following command:
```
$ sudo yum --enablerepo=remi install php-pecl-crypto
```

#### PECL

This extension is available on PECL. The package is not currently stable.
If the config `preferre_state` is stable, then the version needs to be specified.

```
$ sudo pecl install crypto-0.x.y
```

where `x` is an installed minor version number and `y` bug fixing version number.


#### Manual Installation

It's important to have a git installed as it's necessary for recursive fetch of
[phpc](https://github.com/bukka/phpc).

First clone recursively the repository
```
git clone --recursive https://github.com/bukka/php-crypto.git
```

Then go to the created directory and compile the extension. The PHP development
package has to be installed (command `phpize` must be available).
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

Be aware that master branch contains a slightly different error handling.
You can see examples for more details.

### Windows

Precompiled binary `dll` libraries for php-crypto are available
on [the PECL crypto page](http://pecl.php.net/package/crypto).

The php-crypto `dll` is also available in Jan-E Windows builds
on [Apache Lounge](https://www.apachelounge.com/viewforum.php?f=6).


## API

The extension is still in development so the API is not stabilized yet.

All classes are defined in namespace `Crypto`.

Each base class has an exception class that has the same name and
`Exception` suffix (e.g. `Hash` class has `HashException`. The exception
classes are subclasses of the PHP `Exception` class. They define
exception code as class constants. Each code also has a different message.

### PHP definition for the classes

The PHP based DocBlock documenation for all classes is
generated from the extension code. It can be found in
[docs/Crypto.php](docs/Crypto.php). It can be also
used for an IDE autocomplete.

### Hash

The `Hash` class provides functions for creating message digest from a supplied
block of data. It allows to choose an algorithm and contains additional methods
giving more info like it's block size.

#### `Hash::__construct($algorithm)`

_**Description**_: Creates a new `Hash` class if supplied algorithm is supported.

The constructor first check if the algorithm is found. If it's not then
`HashException` is thrown. Otherwise a new instance of `HashException`

##### *Parameters*

*algorithm* : `string` - the algorithm name (e.g. `sha256`, `sha512`, `md5`)

##### *Return value*

`Hash`: New instances of the class

##### *Throws*

It can throw `HashException` with code

- `HashException::ALGORITHM_NOT_FOUND` - the supplied algorithm is not found

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

#### `Hash::__callStatic($name, $arguments)`

_**Description**_: Creates hash digest using static call syntax.

The usage of `__callStatic` magic method allows simplified syntax for creating
`Hash` object (e.g. `Hash::sha256($message)`). The `$name` depicts the algorithm
which is checked if it's found. If not then `HashException` is thrown. Otherwise
the new `Hash` instance is returned.

##### *Parameters*

*name* : `string` - the algorithm name (e.g. `sha256`, `sha512`, `md5`)
*arguments* : `array` - there can be just one element which is message

##### *Return value*

`Hash`: New instances of the class

##### *Throws*

It can throw `HashException` with code

- `HashException::ALGORITHM_NOT_FOUND` - the algorithm (name) is not found

##### *Examples*

```php
echo \Crypto\Hash::sha256('abc')->hexdigest();
```

#### `Hash::digest()`

_**Description**_: Returns a hash digest in binary encoding

This method returns a binary digest. It also finalizes the hash
context which means that if `Hash::update` is called again,
then the context is reinitialized - the result is the same
like creating a new object using the same algorithm and then
call `Hash::update` on it.

If the hash object has not been updated, then the result will
be a hash for the empty string.

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

_**Description**_: Returns a hash algorith name

It is a getter for internal `Hash::$algorithm` reod only property
which is set during the object construction.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`string`: The name of the hash algorithm (e.g. `sha256`)

##### *Examples*

```php
$hash = new \Crypto\Hash('sha256');
// this will output sha256
echo $hash->getAlgorithmName();
```

#### `Hash::getAlgorithms($aliases = false, $prefix = null)`

_**Description**_: Returns all hash algorithms

This static method returns all hash algorithms. Their parameters
allow filtering of the result. Some algorithms have aliases that
can be returned if the `$aliases` parameter is `true`. The `$prefixe`
allows filtering by the supplied prefix string.

##### *Parameters*

*aliases* : `bool` - whether to show aliases
*prefix* : `string` - prefix that is used for filtering the result

##### *Throws*

This method does not throw any exception.

##### *Return value*

`array`: list of supported hash alorithms

##### *Examples*

```php
print_r(\Crypto\Hash::getAlgorithms());
```

#### `Hash::getBlockSize()`

_**Description**_: Returns the hash block size in bytes

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

_**Description**_: Returns the hash output size in bytes

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

### Streams

The new crypto stream API adds a new stream `crypto.file://`.

The supported context options are following:

- `cipher` => array - Cipher filter (`BIO_f_cipher`). The array can contain following fields:
  - `action` => *string* (`encrypt`|`decrypt`) - whether to encrypt or decrypt data
  - `algorithm` => *string* - algorithm name
  - `mode` => *string*|*int* - cipher mode (optional - if not set, then it must be part of algorithm name)
  - `key_size` =>  *string*|*int* - key size for the algorithm  (optional - if not set, then it must be part of algorithm name)
  - `key` => *string* - key string
  - `iv` => *string* - initial vector string
  - `tag` => *string* - authentication tag (optional and only for auth modes and action `decrypt`)
  - `aad` => *string* - additional application data (optional only for auth modes)

If a `mode` is `GCM` and an action is `encrypt`, then the resulted tag can be found in stream meta
as
```
X-PHP-Crypto-Auth-Tag: <tag>
```

If the action for GCM mode is `descrypt`, then the result can be found as
```
X-PHP-Crypto-Auth-Result: <result>
```
where `<result>` can be either `success` or `failure`.

Code examples can be found in [](examples/stream_cipher_gcm.php) for GCM mode and
[](examples/stream_cipher_cbc.php) for simple CBC mode.


## Examples

The examples can be found in [the example directory](examples).


## TODO list

There is lots of features on the [TODO list](TODO.md).


## History

The release history can be found [HISTORY.md](HISTORY.md).

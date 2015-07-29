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

*algorithm* : string - the algorithm name (e.g. `sha256`, `sha512`, `md5`)

##### *Return value*

*Hash*: New instances of the class

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
    $hash = new \Crypto\Hash('sha256');
}
catch (\Crypto\HashException $e) {
    echo $e->getMessage();
}
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

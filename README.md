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

### PHP definition for the classes

As the extension is still in development, the documenation for all classes is
generated from the extension code. It can be found in
[docs/Crypto.php](docs/Crypto.php) which can be also used for an IDE autocomplete.

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

```


## Examples

The examples can be found in [the example directory](examples).


## TODO list

There is lots of features on the [TODO list](TODO.md).


## History

The release history can be found [HISTORY.md](HISTORY.md).

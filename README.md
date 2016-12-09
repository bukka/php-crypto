# PHP OpenSSL Crypto wrapper

The php-crypto is an objective wrapper for OpenSSL Crypto library.


## Installation

### Linux

Before starting with installation of this extensions, the `OpenSSL` library
has to be installed. It is defaultly installed on the most Linux distributions.
The minimal version of OpenSSL that is supported is 0.9.8 but it is recommended
to have installed version 1.0.1+ to use all features. 

Of course PHP has to be installed too. The minimal version that is supported is
5.3 as the extension uses namespaces. Currently PHP also needs to be compiled
with OpenSSL extension (`--with-openssl`). This dependency will be removed
in the future.

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

The documentation is devided to sections where can be found documentation
of all class methods, constants and other related details:

- **[Base64](docs/base64.md)**
- **[Cipher](docs/cipher.md)**
- **[CMAC](docs/cmac.md)**
- **[Hash](docs/hash.md)**
- **[HMAC](docs/hmac.md)**
- **[MAC](docs/mac.md)**
- **[KDF](docs/kdf.md)**
- **[PBKDF2](docs/pbkdf2.md)**
- **[Rand](docs/rand.md)**
- **[Streams](docs/streams.md)**


### PHP definition for the classes

The PHP based DocBlock documenation for all classes is
generated from the extension code. It can be found in
[docs/Crypto.php](docs/Crypto.php). It can be also
used for an IDE autocomplete.


## Examples

The examples can be found in [the example directory](examples).


## TODO list

There is lots of features on the [TODO list](TODO.md).


## History

The release history can be found [HISTORY.md](HISTORY.md).

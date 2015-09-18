## Rand

The `Rand` class provides set of static functions for getting
random values. It includes functions for adding entropy to
the PRNG algorithm.

### Static Methods

#### `Rand::generate($num, $must_be_strong, &$returned_strong_result)`

_**Description**_: Generates and returns random data

The `Rand::generate` method generates data from seeded buffer.
The buffer is seeded automatically when the extension is initialized.
Entropy can be added using `Rand::seed`.

The second parameter `$must_be_strong`, whose default value is true,
specify whether the returned bytes are cryptographically strong
pseudo-random bytes. If it's `false`, then information whether
the bytes are strong is saved in the third parameter. If it's `true`
and data are not strong, a `RandException` is thrown

When using a default Rand implementation on Linux or BSD, then it's
very unlikely to get bytes that are not strong. It means that
the second and third parameters can be ignored and just
specify `$num` and then possibly handle an exception.

##### *Parameters*

*num* : `int` - the number of bytes that are returned (string length)
*must_be_strong* : `bool` - whether the result has to be strong -
default is `true`
*returned_strong_result* : `bool` reference - output variable
which stores information whether the generated result is strong

##### *Return value*

`string`: Random data.

##### *Throws*

It can throw `RandException` with code

- `RandException::REQUESTED_BYTES_NUMBER_TOO_HIGH` - if the number
of requested random bytes (`$num`) is greater than C `INT_MAX`
- `RandException::GENERATE_PREDICTABLE` - if `$must_be_strong`
is `true` and the returned result is not strong.

##### *Examples*

```php
$iv = \Crypto\Rand::generate(16);
```

#### `Rand::seed($buf, $entropy)`

_**Description**_: Mixes supplied data into the PRNG state

This method mixes data in `$buf` into the internal PRNG state. It
means that it's not an actual seeding on its own but more adding
an extra entropy. The estimated value of entropy can be supplied
as the second parameter `$entropy`. If it's not specified, then
length of the buffer is used.

##### *Parameters*

*buf* : `int` - a buffer to be mixed into the PRNG state
*entropy* : `float` - estimated entropy of the data in `$buf`

##### *Return value*

`null`: Nothing is returned.

##### *Throws*

It can throw `RandException` with code

- `RandException::SEED_LENGTH_TOO_HIGH` - if the length of
the buffer is greater than C `INT_MAX`

##### *Examples*

```php
\Crypto\Rand::seed($buf);
```

#### `Rand::cleanup()`

_**Description**_: Erases the PRNG state

This method globally erases the memory that is used by PRNG.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`null`: Nothing is returned.

##### *Examples*

```php
\Crypto\Rand::cleanup();
```

#### `Rand::loadFile($filename, $max_bytes)`

_**Description**_: Reads data from file and mixes them to the PRNG
state

This method mixes data from the file in `$filename` into
the internal PRNG state. It reads at most `$max_bytes` bytes.

##### *Parameters*

*filename* : `string` - file path of the file that is read
*max_bytes* : `int` - maximal number of bytes that is read
from file

##### *Return value*

`int`: The number of bytes read.

##### *Throws*

It can throw `RandException` with code

- `RandException::REQUESTED_BYTES_NUMBER_TOO_HIGH` - if the supplied
`$max_bytes` is greater than C `INT_MAX`

##### *Examples*

```php
\Crypto\Rand::loadFile($filename, 1024);
```

#### `Rand::writeFile($filename)`

_**Description**_: Writes random bytes to the file

This method writes 1024 bytes the the file `$filename`. It
can be used later to initial PRNG state by calling
`Rand::load`.

##### *Parameters*

*filename* : `string` - file path of the file where
random data are written.

##### *Return value*

`int`: The number of bytes read.

##### *Throws*

It can throw `RandException` with code

- `RandException::REQUESTED_BYTES_NUMBER_TOO_HIGH` - if the written
bytes were generated without appropriate seed.

##### *Examples*

```php
\Crypto\Rand::writeFile($filename);
```

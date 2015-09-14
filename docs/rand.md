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

#### `Rand::cleanup()`

#### `Rand::loadFile($filename, $max_bytes)`

#### `Rand::writeFile($filename)`
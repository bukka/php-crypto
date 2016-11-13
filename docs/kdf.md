## KDF

The `KDF` abstract class represent base class for all Key Derivation Functions.
It is a parent of [`PBKDF2`](pbkdf2.md).

### Instance Methods

#### `KDF::__construct($length, $salt = NUL)`

_**Description**_: Creates a new `KDF` class.

The `KDF` class is an abstract class which means that it can't be instantiated.
This constructor defines just logic for its subclasses. It sets a supplied
length and salt if supplied. It can throw `KDFException` if the salt size
or length is over the max limits.

##### *Parameters*

*length* : `int` - the key length
*salt* : `string` - the salt

##### *Return value*

`KDF`: New instances of the `KDF` subclass.

##### *Throws*

It can throw `KDFException` with code

- `MACException::KEY_LENGTH_LOW` - the supplied key length is too low
- `MACException::KEY_LENGTH_HIGH` - the supplied key length is too high
- `MACException::SALT_LENGTH_HIGH` - if the data length exceeds
C INT_MAX


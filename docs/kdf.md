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

#### `KDF::derive($password)`

_**Description**_: An abstract method to derive the key from the password.

The `derive` abstract method has to be used in all subclasses to derive
the key from the supplied password. If the derivation fails, it must
throw `KDFException`.

##### *Parameters*

*password* : `string` - the password

##### *Return value*

`string`: Derived key.

##### *Throws*

The implementing method can throw `KDFException` with code

- `MACException::DERIVATION_FAILED` - the derivation failed
- `MACException::PASSWORD_LENGTH_INVALID` - if the password length
exceeds C INT_MAX

#### `KDF::getLength()`

_**Description**_: Returns a length of the derived key.

This method returns a lenght of the key that will be or was derived
by the `KDF::derive`.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`int`: The lenght of the derived key.

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

- `KDFException::KEY_LENGTH_LOW` - the supplied key length is too low
- `KDFException::KEY_LENGTH_HIGH` - the supplied key length is too high
- `KDFException::SALT_LENGTH_HIGH` - if the data length exceeds
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

- `KDFException::DERIVATION_FAILED` - the derivation failed
- `KDFException::PASSWORD_LENGTH_INVALID` - if the password length
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

#### `KDF::getSalt()`

_**Description**_: Returns salt for the key derivation.

This method returns salt string that will be used when deriving a key
using `KDF::derive`.

##### *Parameters*

This method has no parameters.

##### *Throws*

This method does not throw any exception.

##### *Return value*

`string`: The salt.

#### `KDF::setLength($length)`

_**Description**_: Sets a length for the derived key.

This method sets a length that will be the string length of the derived key.

##### *Parameters*

*length* : `int` - key length

##### *Throws*

It can throw `KDFException` with code

- `KDFException::KEY_LENGTH_LOW` - if key length is less than 0
- `KDFException::KEY_LENGTH_HIGH` - if key length is more than C INT_MAX
value

##### *Return value*

`bool`: true if the key length was set succesfully

#### `KDF::setSalt($salt)`

_**Description**_: Sets salt for the key derivation.

This method sets salt that will be used when deriving key using `KDF::derive`.

##### *Parameters*

*salt* : `string` - salt for the key derivation

##### *Throws*

It can throw `KDFException` with code

- `KDFException::SALT_LENGTH_HIGH` - if the salt length is more than C INT_MAX

##### *Return value*

`bool`: true if the salt was set succesfully

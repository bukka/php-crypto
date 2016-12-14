## MAC

The `MAC` abstract class extends [`Hash`](hash.md) class. It is
a parent of [`HMAC`](hmac.md) and [`CMAC`](hmac.md).

### Instance Methods

#### `MAC::__construct($key, $algorithm)`

_**Description**_: Creates a new `MAC` class if supplied algorithm is supported.

The `MAC` class is an abstract class which means that it can't be instantiated.
This constructor defines just logic for its subclasses. It sets a supplied
key and throws `MACException` if one of its subclasses does not implement the
supplied algorithm.

##### *Parameters*

*key* : `string` - the key string
*algorithm* : `string` - the algorithm name

##### *Return value*

`MAC`: New instances of the `MAC` subclass.

##### *Throws*

It can throw `MACException` with code

- `MACException::HASH_ALGORITHM_NOT_FOUND` - the supplied algorithm is not found
- `MACException::KEY_LENGTH_INVALID` - the supplied key length is incorrect


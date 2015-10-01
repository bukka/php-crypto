## Base64

The `Base64` class provides functions for encoding and decoding data
to and from base64 encoding.

### Static Methods

#### `Base64::decode($data)`

_**Description**_: Decodes base64 encoded data

This static method decodes supplied base64 encoded data. The data has
to be wrapped into the lines of 80 characters followed by a new line
character. This format is typical for encoding crypto keys (e.g. PEM).
If there is a line with more than 80 characters or data are incorrectly
encoded, then `Base64Exception` is thrown.

##### *Parameters*

*data* : `string` - base64 encoded data for decoding

##### *Throws*

It can throw `Base64Exception` with code

- `Base64Exception::DECODE_UPDATE_FAILED` - if the data are incorrectly
encoded or wrapped.
- `Base64Exception::INPUT_DATA_LENGTH_HIGH` - if the data length exceeds
C `INT_MAX`

##### *Return value*

`string`: Decoded data.

##### *Examples*

```php
try {
    $data = \Crypto\Base64::decode($base64_data);
} catch (\Crypto\Base64Exception $e) {
    echo $e->getMessage();
}
```

#### `Base64::encode($data)`

_**Description**_: Encodes data to base64 encoding

This static method encodes supplied data using base64 encoding. The data
is written in lines of 80 characters. This format is typical for encoding
crypto keys (e.g. PEM).

##### *Parameters*

*data* : `string` - data to encode

##### *Throws*

It can throw `Base64Exception` with code

- `Base64Exception::INPUT_DATA_LENGTH_HIGH` - if the data length exceeds
C `INT_MAX`

##### *Return value*

`string`: Base64 encoded data.

##### *Examples*

```php
$base64_data = \Crypto\Base64::encode($data);
```

### Instance Methods

#### `Base64::__construct()`

_**Description**_: Creates a new Base64 object

The constructor initializes `Base64` context for encoding or decoding.

##### *Parameters*

The constructor does not have any parameters.

##### *Throws*

The constructor does not throw any exception.

##### *Return value*

`Base64`: New instances of the `Base64` class.

##### *Examples*

```php
$base64 = new \Crypto\Base64();
```

#### `Base64::decodeFinish()`

_**Description**_: Finishes the base64 decoding

This method finishes base64 decoding and returns resulted data
if they are buffered (mostly it returns just empty string)

##### *Parameters*

This method does not have any parameters.

##### *Throws*

It can throw `Base64Exception` with code

- `Base64Exception::ENCODE_FINISH_FORBIDDEN` - if the context
has not been updated using `Base64::decodeUpdate`


##### *Return value*

`string`: Decoded string if there is something in the buffer, otherwise
an empty string.

##### *Examples*

```php
$base64 = new \Crypto\Base64();
$decoded_data = $base64->decodeUpdate($base64_data);
$decoded_data .= $base64->decodeFinish();
```


#### `Base64::decodeUpdate($data)`

_**Description**_: Updates the base64 decoding context

This method updates base64 decoding context with suppplied data. It
also returns the decoded data.

The data has to be wrapped into the lines of 80 characters followed by
a new line character. This format is typical for encoding crypto keys
(e.g. PEM). If there is a line with more than 80 characters or data
are incorrectly encoded, then `Base64Exception` is thrown.

##### *Parameters*

*data* : `string` - base64 encoded data for decoding

##### *Throws*

It can throw `Base64Exception` with code

- `Base64Exception::DECODE_UPDATE_FAILED` - if the data are incorrectly
encoded or wrapped.
- `Base64Exception::INPUT_DATA_LENGTH_HIGH` - if the data length exceeds
C `INT_MAX`

##### *Return value*

`string`: Decoded data.

##### *Examples*

```php
try {
    $base64 = new \Crypto\Base64();
    $data = '';
    while (($base64_data = read_base64_encoded_data()) !== null) {
        $data .= $base64->decodeUpdate($base64_data);
    }
    $data .= $base64->decodeFinish();
} catch (\Crypto\Base64Exception $e) {
    echo $e->getMessage();
}
```

#### `Base64::encodeFinish()`

_**Description**_: Finishes the base64 encoding

This method finishes base64 encoding and returns base64 encoded data
if they are any buffered or empty string otherwise.

##### *Parameters*

This method does not have any parameters.

##### *Throws*

This method doesn't throw any exception.

##### *Return value*

`string`: Encoded string if there is something in the buffer, otherwise
an empty string.

##### *Examples*

```php
$base64 = new \Crypto\Base64();
$base64_data = $base64->encodeUpdate($data);
$base64_data .= $base64->decodeFinish();
```

#### `Base64::encodeUpdate($data)`

_**Description**_: Updates the base64 encoding context

This method updates base64 encoding context with suppplied data. It
also returns the encoded data.

The data is written in lines of 80 characters. This format is typical
for encoding crypto keys (e.g. PEM).

##### *Parameters*

*data* : `string` - data to encode

##### *Throws*

It can throw `Base64Exception` with code

- `Base64Exception::INPUT_DATA_LENGTH_HIGH` - if the data length exceeds
C `INT_MAX`

##### *Return value*

`string`: Base64 encoded data.

##### *Examples*

```php
$base64 = new \Crypto\Base64();
$base64_data = '';
while (($data = read_data_for_encoding()) !== null) {
    $base64_data .= $base64->encodeUpdate($data);
}
$base64_data .= $base64->encodeFinish();
```
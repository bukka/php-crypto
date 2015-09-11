## Streams

Crypto registers a stream called `crypto.file://`. As the name
suggests, it has to be used with files only. The prefix is
followed by the file path. All options has to be passed
using stream context.

### Options

Cipher context is created using `stream_context_create` function
which accepts an array of parameters. Options for crypto are under
an array with key `crypto`. That has to contain an array
of filters that are applied to the stream when reading or
writing. It's done in the same order as the array indexes
(first item in the array is applied first, second item is applied
after that and so on).

For example a context definition for stream with one cipher filter
could look like:

```php
$context_write = stream_context_create(array(
    'crypto' => array(
        'filters' => array(
            array(
                'type' => 'cipher',
                'action' => 'encrypt',
                'algorithm' => 'AES-128-CBC',
                'key' => $key,
                'iv'  => $iv,
            )
        )
    ),
));
```

The `type` item in the filter identifies a type. Currently only
`cipher` is allowed but more filter types may be added in
the future.

#### Filter: cipher

The `cipher` filter can have following options for the filter
(all fields that are not optional are required):

- `action` => *string* (`encrypt`|`decrypt`) - whether to encrypt
or decrypt data
- `algorithm` => *string* - algorithm name
- `mode` => *string*|*int* - cipher mode (optional - if not set,
then it must be part of algorithm name)
- `key_size` =>  *string*|*int* - key size for the algorithm
(optional - if not set, then it must be part of algorithm name)
- `key` => *string* - key string
- `iv` => *string* - initial vector string (optional for ECB
mode and ciphers that does not require IV)
- `tag` => *string* - authentication tag (optional and only
for auth modes and action `decrypt`)
- `aad` => *string* - additional application data (optional only
for auth modes)

If a `mode` is `GCM` and an action is `encrypt`, then the resulted
tag can be found in stream meta as
```
X-PHP-Crypto-Auth-Tag: <tag>
```

If the action for GCM mode is `descrypt`, then the result can be
found as
```
X-PHP-Crypto-Auth-Result: <result>
```
where `<result>` can be either `success` or `failure`.

A CCM mode is not supported for stream because data can be updated
just once which doesn't make sense for stream operations.

### Example

Code examples can be found in
[stream_cipher_gcm.php](../examples/stream_cipher_gcm.php) for GCM
mode and [stream_cipher_cbc.php](../examples/stream_cipher_cbc.php)
for simple CBC mode.


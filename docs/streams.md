## Streams

Crypto registers a stream called `crypto.file://`. As the name
suggest, it's meant for files. The prefix is followed by the
file path. All options has to be passed using stream context

### Options

Cipher context is created using `stream_context_create` function
which accept array of parameters. Options for crypto are under
the key `crypto`. That can contain array of filters that are
applied on the stream when reading or writing in the order they
are supplied. For example a context definition for stream with
one cipher filter could look like:

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

The `type` item in the filter identifies the type. Currently only
`cipher` is allowed but more filter types may be added in the future.

#### Filter: cipher

The `cipher` filter type allows following options for the filter:

- `action` => *string* (`encrypt`|`decrypt`) - whether to encrypt
or decrypt data
- `algorithm` => *string* - algorithm name
- `mode` => *string*|*int* - cipher mode (optional - if not set,
then it must be part of algorithm name)
- `key_size` =>  *string*|*int* - key size for the algorithm
(optional - if not set, then it must be part of algorithm name)
- `key` => *string* - key string
- `iv` => *string* - initial vector string
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

Code examples can be found in [](examples/stream_cipher_gcm.php) for
GCM mode and [](examples/stream_cipher_cbc.php) for simple CBC mode.

A CCM mode is not supported for stream because data can be updated
just once and that wouldn't work well with PHP streams.


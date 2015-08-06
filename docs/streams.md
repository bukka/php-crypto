## Streams

The new crypto stream API adds a new stream `crypto.file://`.

The supported context options are following:

- `cipher` => array - Cipher filter (`BIO_f_cipher`). The array can contain following fields:
  - `action` => *string* (`encrypt`|`decrypt`) - whether to encrypt or decrypt data
  - `algorithm` => *string* - algorithm name
  - `mode` => *string*|*int* - cipher mode (optional - if not set, then it must be part of algorithm name)
  - `key_size` =>  *string*|*int* - key size for the algorithm  (optional - if not set, then it must be part of algorithm name)
  - `key` => *string* - key string
  - `iv` => *string* - initial vector string
  - `tag` => *string* - authentication tag (optional and only for auth modes and action `decrypt`)
  - `aad` => *string* - additional application data (optional only for auth modes)

If a `mode` is `GCM` and an action is `encrypt`, then the resulted tag can be found in stream meta
as
```
X-PHP-Crypto-Auth-Tag: <tag>
```

If the action for GCM mode is `descrypt`, then the result can be found as
```
X-PHP-Crypto-Auth-Result: <result>
```
where `<result>` can be either `success` or `failure`.

Code examples can be found in [](examples/stream_cipher_gcm.php) for GCM mode and
[](examples/stream_cipher_cbc.php) for simple CBC mode.


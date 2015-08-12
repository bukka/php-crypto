## Cipher

The `Cipher` class handles all encryption and decription including AEAD 
as well as provides various information about selecte cipher algorithm.

### Constants

#### `Cipher::MODE_CCM`

#### `Cipher::MODE_CBC`

#### `Cipher::MODE_CFB`

#### `Cipher::MODE_CTR`

#### `Cipher::MODE_ECB`

#### `Cipher::MODE_GCM`

#### `Cipher::MODE_OFB`

#### `Cipher::MODE_XTS`


### Static Methods

#### `Cipher::__callStatic($name, $arguments)`

#### `Cipher::getAlgorithms($aliases = false, $prefix = null)`

#### `Cipher::hasAlgorithm($algorithm)`

#### `Cipher::hasMode($mode)`


### Instance Methods

#### `Cipher::__construct($algorithm)`

#### `Cipher::decrypt($data, $key, $iv = null)()`

#### `Cipher::decryptFinish()`

#### `Cipher::decryptInit($key, $iv = null)`

#### `Cipher::decryptUpdate($data) `

#### `Cipher::encrypt($data, $key, $iv = null)`

#### `Cipher::encryptFinish()`

#### `Cipher::encryptInit($key, $iv = null)`

#### `Cipher::encryptUpdate($data)`

#### `Cipher::getAlgorithmName()`

#### `Cipher::getBlockSize()`

#### `Cipher::getIVLength()`

#### `Cipher::getKeyLength()`

#### `Cipher::getMode()`

#### `Cipher::getTag($tag_size)`

#### `Cipher::setAAD($aad)`

#### `Cipher::setTag($tag)`

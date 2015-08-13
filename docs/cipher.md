## Cipher

The `Cipher` class handles all encryption and decription including AEAD 
as well as provides various information about selecte cipher algorithm.

### Constants

#### `Cipher::MODE_CCM`

The CCM (Counter with CBC-MAC) is an authenticated mode. It requires
a length pre-initialization which means that a plain resp. cipher
text must be known before encryption resp. decription. That makes
it unsituable for streams or continuous cipher update. 

#### `Cipher::MODE_CBC`

The CBC (Cipher Block Chaining) mode XOR the previos block with the
currently en/decrypted one. It requires random IV to be set.

#### `Cipher::MODE_CFB`

The CFB (Cipher FeedBack) mode makes a block ciphper into
a self-synchronizing stream cipher.

#### `Cipher::MODE_CTR`

The CTR (CounTeR) mode is using counter and a random nonce.

#### `Cipher::MODE_ECB`

The ECB (Electronic Codebook) mode is an insecure mode susceptible
on replay attack if a message length is greater than a block length.

#### `Cipher::MODE_GCM`

The GCM (Golias Counter Mode) is an authenticated mode.

#### `Cipher::MODE_OFB`

The OFB (Output FeedBack) mode makes a block cipher into 
a synchronous stream cipher

#### `Cipher::MODE_XTS`

The XTS (XEX-based tweaked codebook mode with ciphertext stealing) mode
is a mode designed for hard disk storage.


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

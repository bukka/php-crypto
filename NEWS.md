# News

List of all features for the release

## 0.3.0
- Fixed compilation with OpenSSL 1.1 and PHP 7.1
- Added KDF abstract class to be a parent for all key derivation function classes
- Added PBKDF2 class extending KDF class and implementing PBKDF2
- Renamed HashException code ALGORITHM_NOT_FOUND to HASH_ALGORITHM_NOT_FOUND
- Renamed MACException code ALGORITHM_NOT_FOUND to MAC_ALGORITHM_NOT_FOUND

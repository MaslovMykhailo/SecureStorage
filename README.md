# Secure Storage

Simple web application with client authentication which allows storing sensitive (private) user information

### Implementation

- Application was implemented using [Spring Boot Framework](https://spring.io/projects/spring-boot)
- As data storage was chosen MySQL database
- Web server and database are running in Docker containers

## lab 5 report

#### Input validation

- Username has to be between 8 and 64 symbols length, any characters except of whitespaces are allowed
- Password has to be between 8 and 64 symbols length too
- For a password allowed any characters except whitespaces
- Password has to contain at least one uppercase character
- Password has to contain at least one digit
- Password has to contain at least one special character
- Password cannot contain more than 5 sequential numeric characters
- Password cannot contain more than 5 sequential alphabetical characters
- Password cannot contain more than 3 sequential characters in order as symbols are positioned in qwerty keyboard
- Password strength is checked using [zxcvbn](https://github.com/nulab/zxcvbn4j) password strength estimator

#### Data storing 

- Username is stored in database as is
- Password hash is stored in database

#### Password hashing

- Password hashed using [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) algorithm
- Password has to be less than or equal 64 symbols length to satisfy the requirements of bcrypt
- No pre-hashing used
- Password salted by bcrypt under the hood 
- Bcrypt is provided by [Spring Security](https://spring.io/projects/spring-security)
- Bcrypt is configured by default with work factor equals 10

#### Resources

- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-storage-cheat-sheet

## lab 6 report

#### Input validation

- Any characters are allowed as user sensitive data

#### Data storing

- User sensitive data is encrypted, encoded and stored in database

#### Data encryption

- For user sensitive data used few steps encryption
- Firstly, data encryption key is generated using *javax.crypto.KeyGenerator* with AES algorithm configuration, key size is 128 bits
- Secondly, data is encrypted with previously create key using AES algorithm in GCM mode, also 12 bytes initialisation vector is generated using *java.security.SecureRandom*
- Thirdly, data encryption key is encrypted using [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html), also using AES in GCM mode, but with 256 bits key size
- The key which was used for data encryption key encryption is stored in [AWS KMS](https://aws.amazon.com/en/kms)
- Finally, encrypted key and data are encoded into base64 and stored in database

#### Prevented attack vectors

- Data breach and data leaks prevented because when attacker compromise data of some user, it is not possible to get access to other users' data using compromised one, encryption key stored in AWS KMS and data encryption key protect data
- SQL injections prevented because sensitive data stored in encrypted and encoded form
- Session hijacking also prevented for not compromised users by using two keys for encryption data and key, because each user sensitive data encrypted by the unique key, which is also encrypted

### Not prevented attack vectors

- Stealing AWS KMS credentials and key id which allows to decrypt any data encryption key
- OS penetration and stealing database credentials

#### Resources

- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#cryptographic-storage-cheat-sheet
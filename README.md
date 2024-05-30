# Passkeep password manager

Passkeep is a proof-of-concept password manager that is good for personal use. This is Based ontop of [leetCypher](https://github.com/leetCipher)'s password generator. I added a GUI and fixed a few Bugs. This is not perfect, so please report Bugs and issues to me!

## Installation

You will need to first install the required modules in the requirements.txt file:

```bash
pip3 install -r requirements.txt
chmod +x passkeep.py
./passkeep.py
```

## Security
Passkeep uses AES-CBC modes of operation to encrypt all the credentials in the "passwords.db" file and uses SHA-256 hash function to hash and validate the key that is used for both encryption and decryption.

## Features
* Add, Edit, Delete credentials
* Change the encryption/decryption key
* Passwords generation
* Backup database/credentials
* Erase database/credentials

## Bugs
I tested the application several times to make sure it's bug free (that doesn't mean it is), so in case of any bugs (insecure cryptographic implementations/weaknesses only), please, report the issue.
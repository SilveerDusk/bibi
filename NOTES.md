# TODO

## Defense:
- Add a check-sum to the encrypted file for data integrity check before read/write/add secret
    - AES CBC is implemented, which doesn't provide integrity protection
- Check password hashing function
- Check for memory bad practices
    - In case of an error, catch and handle memory allocations. Exit normally

## Attack:
- Account takeover using an existing key to overwrite the password
- Method in which the password is written in the file
    - If password is written "user1 password1" + "\n" + "user2 password2" then user2's password be overwritten.

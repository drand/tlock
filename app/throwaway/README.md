# PLEASE READ THIS FIRST

### This is a throwaway code meant to test some functionality.

The `main` function is calling both encrypt and decrypt. You have to manually comment/uncomment them as you wish.

```go
go run main.go
```
This will generate a file called `encryptedData`, containing base64 data separated by a dot (like JWT).

It will encrypt using a beacon that is 30 seconds in the future. *(You can change that value in the function parameter)*

This command will output something like this:
```
Future round to use for decryption:  1273234
```
That number is the future round number. Copy it and paste it into the decrypt function call.

Comment the encrypt function and uncomment decrypt, and run the code again.

If it fails with an EOF error, it means that the round is not yet available.
You can check with this request: http://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf/public/latest.
It will return the latest one available.

When the round is available you will be able to decrypt the file and get this message in your terminal:
```
Message: Secret message
``` 
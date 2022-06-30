# tlock: Timelock Encryption made practical

tlock gives you time based encryption and decryption capabilities using a Drand network. It is also a Go library.

# Usage

```bash
Usage:
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [INPUT]
	tle --decrypt [-o OUTPUT] [INPUT]

Options:
	-e, --encrypt  Encrypt the input to the output. Default if omitted.
	-d, --decrypt  Decrypt the input to the output.
	-n, --network  The drand API endpoint to use.
	-c, --chain    The chain to use. Can use either beacon ID name or beacon hash. Use beacon hash in order to ensure public key integrity.
	-r, --round    The specific round to use to encrypt the message. Cannot be used with --duration.
	-D, --duration How long to wait before the message can be decrypted.
	-o, --output   Write the result to the file at path OUTPUT.
	-a, --armor    Encrypt to a PEM encoded format.

If the OUTPUT exists, it will be overwritten.

NETWORK defaults to the Drand test network http://pl-us.testnet.drand.sh/.

CHAIN defaults to the "unchained" hash in the default test network: 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf

When --duration is specified, it expects a value following Golang's type Duration and its units. It also accepts the units for day, month and year: d, M, y.

Example:
    $ tle -D 10d -o encrypted_file data_to_encrypt

After the specified duration:
    $ tle -d -o dencrypted_file.txt encrypted_file
```

## Encryption

Files can be encrypted using a duration (`--duration/-D`) in which the `encrypted_data` can be decrypted.

```bash
$ tle -n="http://pl-us.testnet.drand.sh/" -c="7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -D=5s -o=encrypted_data data.txt
```

If a round (`--round/-R`) number is known, it can be used instead of the duration. The data can be decrypted only when that round becomes available in the network.
```bash
$ tle -n="http://pl-us.testnet.drand.sh/" -c="7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -r=123456 -o=encrypted_data data.txt
```

It is also possible to encrypt the data to a PEM encoded format using the armor (`--armor/-a`) flag.
```bash
$ tle -n="http://pl-us.testnet.drand.sh/" -c="7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -r=123456 -a -o=encrypted_data.PEM data.txt
```

## Decryption

For decryption, it is only necessary to specify the network.

```bash
$ tle -d -n="http://pl-us.testnet.drand.sh/" -o=decrypted_data encrypted_data
```

It is not necessary to use the armor flag to decrype a PEM file.

# License

This project is licensed using the [Permissive License Stack](https://protocol.ai/blog/announcing-the-permissive-license-stack/) which means that all contributions are available under the most permissive commonly-used licenses, and dependent projects can pick the license that best suits them.

Therefore, the project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/drand/drand/blob/master/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/drand/drand/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)


# API

* [Overview](#pkg-overview)
* [Index](#pkg-index)
* [Subdirectories](#pkg-subdirectories)

## <a name="pkg-overview">Overview</a>
Package tlock provides an API for encrypting/decrypting data using
drand time lock encryption. This allows data to be encrypted and only
decrypted in the future.

## <a name="pkg-index">Index</a>
* [Constants](#pkg-constants)
* [func Decrypt(ctx context.Context, out io.Writer, in io.Reader, decoder Decoder, network Network, decrypter Decrypter) error](#Decrypt)
* [func EncryptWithDuration(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, duration time.Duration, armor bool) error](#EncryptWithDuration)
* [func EncryptWithRound(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, roundNumber uint64, armor bool) error](#EncryptWithRound)
* [type CipherDEK](#CipherDEK)
* [type CipherInfo](#CipherInfo)
* [type Decoder](#Decoder)
* [type Decrypter](#Decrypter)
* [type Encoder](#Encoder)
* [type Encrypter](#Encrypter)
* [type Metadata](#Metadata)
* [type Network](#Network)

#### <a name="pkg-files">Package files</a>
[tlock.go](/src/target/tlock.go) 

## <a name="pkg-constants">Constants</a>
``` go
const ErrTooEarly = "too early to decrypt"
```
ErrTooEarly represents an error when a decryption operation happens early.

## <a name="Decrypt">func</a> [Decrypt](/src/target/tlock.go?s=5120:5243#L153)
``` go
func Decrypt(ctx context.Context, out io.Writer, in io.Reader, decoder Decoder, network Network, decrypter Decrypter) error
```
Decrypt will decrypt the data that is read by the reader and writes the
original data to the output.

## <a name="EncryptWithDuration">func</a> [EncryptWithDuration](/src/target/tlock.go?s=3441:3612#L100)
``` go
func EncryptWithDuration(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, duration time.Duration, armor bool) error
```
EncryptWithDuration will encrypt the data that is read by the reader which can
only be decrypted in the future specified duration.

## <a name="EncryptWithRound">func</a> [EncryptWithRound](/src/target/tlock.go?s=2927:3091#L89)
``` go
func EncryptWithRound(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, roundNumber uint64, armor bool) error
```
EncryptWithRound will encrypt the data that is read by the reader which can
only be decrypted in the future specified round.

## <a name="CipherDEK">type</a> [CipherDEK](/src/target/tlock.go?s=982:1064#L37)
``` go
type CipherDEK struct {
    KyberPoint []byte
    CipherV    []byte
    CipherW    []byte
}
```
CipherDEK represents the encrypted data encryption key (DEK) needed to decrypt
the cipher data.

## <a name="CipherInfo">type</a> [CipherInfo](/src/target/tlock.go?s=1142:1411#L44)
``` go
type CipherInfo struct {
    Metadata   Metadata  // Metadata provides information to decrypt the CipherDEK.
    CipherDEK  CipherDEK // CipherDEK represents the key to decrypt the CipherData.
    CipherData []byte    // CipherData represents the data that has been encrypted.
}
```
CipherInfo represents the different parts of the fully encrypted output.

## <a name="Decoder">type</a> [Decoder](/src/target/tlock.go?s=2129:2197#L66)
``` go
type Decoder interface {
    Decode(in io.Reader) (CipherInfo, error)
}
```
Decoder knows how to decode CipherInfo from the specified source.

## <a name="Decrypter">type</a> [Decrypter](/src/target/tlock.go?s=2614:2712#L81)
``` go
type Decrypter interface {
    Decrypt(key []byte, cipherData []byte) (plainData []byte, err error)
}
```
Decrypter decrypts cipher data with the specified key.

## <a name="Encoder">type</a> [Encoder](/src/target/tlock.go?s=2271:2397#L71)
``` go
type Encoder interface {
    Encode(out io.Writer, cipherDEK *ibe.Ciphertext, cipherData []byte, md Metadata, armor bool) error
}
```
Encoder knows how to encode CipherInfo to the specified destination.

## <a name="Encrypter">type</a> [Encrypter](/src/target/tlock.go?s=2456:2554#L76)
``` go
type Encrypter interface {
    Encrypt(key []byte, plainData []byte) (cipherData []byte, err error)
}
```
Encrypter encrypts plain data with the specified key.

## <a name="Metadata">type</a> [Metadata](/src/target/tlock.go?s=814:878#L30)
``` go
type Metadata struct {
    RoundNumber uint64
    ChainHash   string
}

```
Metadata represents the metadata that must exist in the encrypted output
to support CipherDEK decryption.

## <a name="Network">type</a> [Network](/src/target/tlock.go?s=1607:2058#L54)
``` go
type Network interface {
    Host() string
    ChainHash() string
    PairingSuite() pairing.Suite
    Client(ctx context.Context) (client.Client, error)
    PublicKey(ctx context.Context) (kyber.Point, error)
    IsReadyToDecrypt(ctx context.Context, roundNumber uint64) (id []byte, ready bool)
    CalculateEncryptionID(roundNumber uint64) ([]byte, error)
    GetEncryptionRoundAndID(ctx context.Context, duration time.Duration) (roundNumber uint64, id []byte, err error)
}
```
Network represents a system that provides support for encrypting/decrypting
a DEK based on a future time.

- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)

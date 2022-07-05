## tlock: Timelock Encryption made practical

tlock gives you time based encryption and decryption capabilities using a Drand network. It is also a Go library.

## Install the CLI

```bash
go install github.com/drand/tlock/cmd@latest
```

## Or Build it

```bash
go build cmd/tle.go
```
This tool is pure Go, it works without CGO (`CGO_ENABLED=0`)

## CLI Usage

```
Usage:
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [INPUT]
	tle --decrypt [-o OUTPUT] [INPUT]

Options:
	-e, --encrypt  Encrypt the input to the output. Default if omitted.
	-d, --decrypt  Decrypt the input to the output.
	-n, --network  The drand API endpoint to use.
	-c, --chain    The chain to use. Can use either beacon ID name or beacon hash. Use beacon hash in order to ensure public key integrity.
	-r, --round    The specific round to use to encrypt the message. Cannot be used with --duration.
	-D, --duration How long to wait before the message can be decrypted. Defaults to 120d (120 days).
	-o, --output   Write the result to the file at path OUTPUT.
	-a, --armor    Encrypt or Decrypt to a PEM encoded format.

If the OUTPUT exists, it will be overwritten.

NETWORK defaults to the Drand test network http://pl-us.testnet.drand.sh/.

CHAIN defaults to the "unchained" hash in the default test network:
7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf

DURATION has a default value of 120d. When it is specified, it expects a number
followed by one of these units: "ns", "us" (or "µs"), "ms", "s", "m", "h", "d", "M", "y").

Example:
    $ tle -D 10d -o encrypted_file data_to_encrypt

After the specified duration:
    $ tle -d -o dencrypted_file.txt encrypted_file
```

### CLI Encryption

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
$ tle -a -n="http://pl-us.testnet.drand.sh/" -c="7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf" -r=123456 -o=encrypted_data.PEM data.txt
```

### CLI Decryption

For decryption, it's only necessary to specify the network.

```bash
$ tle -d -n="http://pl-us.testnet.drand.sh/" -o=decrypted_data encrypted_data
```
If decoding a PEM source.

```bash
$ tle -a -d -n="http://pl-us.testnet.drand.sh/" -o=decrypted_data encrypted_data
```

---

## Library usage

### Encryption and Decryption
```go
// Initialise the network.
// The default host is the Drand test network "http://pl-us.testnet.drand.sh/"
// The default hash is "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
network := http.NewNetwork(host, chainHash)

// Read the data to be encrypted.
in, err := os.Open("data.txt")
if err != nil {
	log.Fatalf("reader error %s", err)
	return
}
defer in.Close()

// Specify the minimum duration your encrypt file should be allowed
// to be decrypted.
duration := 10 * time.Second

// Initialise the encrypter with the given network.
tl := tlock.NewEncrypter(network)

// Use the network to identify the round number from now to the given duration.
roundNumber, err := network.RoundNumber(time.Now().Add(duration))
if err != nil {
	log.Fatalf("round by duration: %s", err)
	return
}

// Write the encoded information to this buffer.
var cipherData bytes.Buffer

// Encrypt the data from the file, with the given round, into cipherData.
err = tl.Encrypt(&cipherData, in, roundNumber)
if err != nil {
	log.Fatalf("encrypt with duration error %s", err)
	return
}

// =========================================================================
// Decrypt

// Write the decoded information to this buffer.
var plainData bytes.Buffer

// If you try to decrypt the data *before* the specified duration, it will
// fail with the message: "too early to decrypt".
err = tlock.NewDecrypter(network).Decrypt(&plainData, &cipherData)
if err == nil {
	log.Fatal("expecting decrypt error")
	return
}

// The buffer plainData now holds the plain data.
```

# License

This project is licensed using the [Permissive License Stack](https://protocol.ai/blog/announcing-the-permissive-license-stack/) which means that all contributions are available under the most permissive commonly-used licenses, and dependent projects can pick the license that best suits them.

Therefore, the project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/drand/drand/blob/master/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/drand/drand/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)

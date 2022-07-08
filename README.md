## tlock: Timelock Encryption/Decryption Made Practical

tlock gives you time based encryption and decryption capabilities using a Drand network. It's also a Go library.

Our timelock encryption system relies on an unchained drand network. Currently, the only publicly available one is the League of Entropy Testnet.

However, it should soon also be available on the LoE Mainnet.

Working endpoints to access it are, for example:
- https://pl-us.testnet.drand.sh/
- https://testnet0-api.drand.cloudflare.com/

You can also spin up a new drand network and run your own, but notice that the security guarantees boil down to the trust you can have in your network.

---

### See How It Works

<p align="center">
	<img src="https://user-images.githubusercontent.com/181501/177999855-cc1cfef7-ee1c-4193-bea7-4ee2e689f2d1.svg"/>
</p>

---

### Table Of Contents
 - [Install the CLI](#install-the-cli)
 - [Build it](#or-build-it)
 - [CLI usage](#cli-usage)
	- [Encryption](#cli-encryption)
	- [Decryption](#cli-decryption)
 - [Library usage](#library-usage)
 - [Using with age CLI](#using-with-age-cli)

---

### Install or Build the CLI

This tool is pure Go, it works without CGO (`CGO_ENABLED=0`)

```bash
go install github.com/drand/tlock/cmd@latest
```

```bash
git clone https://github.com/drand/tlock
go build cmd/tle.go
```

---

### CLI Usage

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

#### Time Lock Encryption

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

#### Time Lock Decryption

For decryption, it's only necessary to specify the network.

```bash
$ tle -d -n="http://pl-us.testnet.drand.sh/" -o=decrypted_data encrypted_data
```

If decoding a PEM source.

```bash
$ tle -a -d -n="http://pl-us.testnet.drand.sh/" -o=decrypted_data encrypted_data
```

---

### Library Usage

These example show how to use the API to time lock encrypt and decrypt data.

#### Time Lock Encryption

```go
// Open an io.Reader to the data to be encrypted.
in, err := os.Open("data.txt")
if err != nil {
	log.Fatalf("open: %s", err)
	return
}
defer in.Close()

// Construct a network that can talk to a drand network.
// host:      "http://pl-us.testnet.drand.sh/"
// chainHash: "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
network := http.NewNetwork(host, chainHash)

// Specify how long we need to wait before the file can be decrypted.
duration := 10 * time.Second

// Use the network to identify the round number that represents the duration.
roundNumber, err := network.RoundNumber(time.Now().Add(duration))
if err != nil {
	log.Fatalf("round by duration: %s", err)
	return
}

// Write the encrypted file data to this buffer.
var cipherData bytes.Buffer

// Encrypt the data for the given round.
if err := tlock.New(network).Encrypt(&cipherData, in, roundNumber); err != nil {
	log.Fatalf("encrypt: %v", err)
	return
}
```

#### Time Lock Decryption

```go
// Open an io.Reader to the data to be decrypted.
in, err := os.Open("data.tle")
if err != nil {
	log.Fatalf("open: %v", err)
	return
}
defer in.Close()

// Construct a network that can talk to a drand network.
// host:      "http://pl-us.testnet.drand.sh/"
// chainHash: "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
network := http.NewNetwork(host, chainHash)

// Write the decrypted file data to this buffer.
var plainData bytes.Buffer

// Decrypt the data. If you try to decrypt the data *before* the specified
// duration, it will fail with the message: "too early to decrypt".
if err := tlock.New(network).Decrypt(&plainData, in); err != nil {
	log.Fatalf("decrypt: %v", err)
	return
}
```

---

### Using with the AGE CLI

You can use the [age](https://github.com/FiloSottile/age) cli to encrypt your data with a passphrase.

#### Encrypting Data With Passphrase
```bash
$ cat data.txt | age -p | tle -D 30s -o encrypted_data
```

#### Decrypting Data With Passphrase
```bash
$ cat encrypted_data | tle -d | age -d -o data.txt
```

---

### License

This project is licensed using the [Permissive License Stack](https://protocol.ai/blog/announcing-the-permissive-license-stack/) which means that all contributions are available under the most permissive commonly-used licenses, and dependent projects can pick the license that best suits them.

Therefore, the project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/drand/drand/blob/master/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/drand/drand/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)

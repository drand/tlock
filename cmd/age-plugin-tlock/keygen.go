package main

import (
	"encoding/hex"
	"fmt"
	"net/url"

	page "filippo.io/age/plugin"
)

func generateKeypair(p *page.Plugin, args []string) error {
	var data []byte
	onlyId := false
	l := len(args)
	switch {
	case l < 3:
		fmt.Println("Generating an interactive identity prompting you for details upon use")

		data = append([]byte{0x02}, []byte("interactive")...)
	case l == 3:

		host, err := url.Parse(args[l-1])
		if err != nil {
			return fmt.Errorf("invalid URL provided in keygen: %w", err)
		}
		if !host.IsAbs() {
			fmt.Println("generating an identity based on the provided signature")
			sig, err := hex.DecodeString(args[l-1])
			if err != nil {
				return fmt.Errorf("invalid URL/signature provided in keygen: %w", err)
			}

			onlyId = true
			data = append([]byte{0x00}, sig...)
		} else {
			fmt.Println("generating a HTTP identity, relying on the network to get data")

			data = append([]byte{0x01}, []byte(host.String())...)
		}
	case l == 4:
		fmt.Println("generating a static recipient, containing the public key and chainhash")

		pkb, err := hex.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("invalid public key hex provided in keygen: %w", err)
		}
		chb, err := hex.DecodeString(args[3])
		if err != nil {
			return fmt.Errorf("invalid chainhash hex provided in keygen: %w", err)
		}

		data = append([]byte{0x00}, pkb...)
		data = append(data, chb...)

		//case l == 5:
	default:
		Usage()
		return nil
	}

	if !onlyId {
		pub := page.EncodeRecipient(p.Name(), data)
		fmt.Println("recipient", pub)
	}

	priv := page.EncodeIdentity(p.Name(), data)
	fmt.Println("identity", priv)
	return nil
}

func Usage() {
	fmt.Println("Usage of age-plugin-tlock:")
	fmt.Printf("\t-keygen\n\t\tgenerate age identity and recipient for age-plugin-tlock usage. You have options:\n\t\t" +
		"use age in interactive mode, getting prompted for all required data:\n\t\t\t" +
		"age-plugin-tlock -keygen\n\t\t" +
		"providing a http endpoint (works for both encryption and decryption, but require networking): \n\t\t\t" +
		"age-plugin-tlock -keygen http://api.drand.sh/\n\t\t" +
		"providing the signature of a given round in hexadecimal, only generates the identity required for decryption with it: \n\t\t\t" +
		"age-plugin-tlock -keygen http://api.drand.sh/\n\t\t" +
		"providing a public key and a chainhash (requires networking to fetch genesis and period, but is networkless afterwards):\n\t\t\t" +
		"age-plugin-tlock -keygen <hexadecimal-public-key> <hexadecimal-chainhash> \n\t\t" +
		//"providing a public key, a chainhash and the signature for the round you're interested in (networkless for decryption): \n\t\t\t" +
		//"age-plugin-tlock -keygen <hexadecimal-public-key> <hexadecimal-chainhash> <hexadecimal-signature>" +
		"\n")
}

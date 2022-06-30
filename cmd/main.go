package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	sphinx "github.com/lightningnetwork/lightning-onion"
	"github.com/urfave/cli"
)

const (
	defaultSessionKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	defaultAssocData  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

// main implements a simple command line utility that can be used in order to
// either generate a fresh mix-header or decode and fully process an existing
// one given a private key.
func main() {
	app := cli.NewApp()
	app.Name = "sphinx-cli"
	app.Commands = []cli.Command{
		{
			Name: "genkeys",
			Usage: "A helper function to generate a random new " +
				"private-public key pair.",
			Action: genKeys,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "priv",
					Usage: "An optional flag to provide " +
						"a private key. In this " +
						"case, this command just " +
						"calculates and prints the " +
						"associated public key",
				},
			},
		},
		{
			Name:   "generate",
			Usage:  "Build a new onion.",
			Action: generate,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "file",
					Usage: "Path to json file containing " +
						"the session key and hops " +
						"data.",
					Required: true,
				},
				cli.StringFlag{
					Name:  "assoc_data",
					Usage: "The associated data to include",
					Value: defaultAssocData,
				},
			},
		},
		{
			Name:   "parse",
			Usage:  "Peel the onion.",
			Action: parse,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name: "onion",
					Usage: "The onion to decode. This " +
						"should be set if the `file` " +
						"flag is not set.",
					Required: true,
				},
				cli.StringFlag{
					Name: "priv",
					Usage: "The private key to be used " +
						"for peeling the onion.",
					Required: true,
				},
				cli.StringFlag{
					Name:  "assocData",
					Usage: "The associated data to include",
					Value: defaultAssocData,
				},
				cli.StringFlag{
					Name: "blinding_point",
					Usage: "The blinding point to use " +
						"when parsing this onion.",
				},
			},
		},
		{
			Name:   "nextblindedpub",
			Action: nextBlindedPub,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:     "priv",
					Required: true,
				},
				cli.StringFlag{
					Name:     "pub",
					Required: true,
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func genKeys(cli *cli.Context) error {
	var (
		priv *btcec.PrivateKey
		pub  *btcec.PublicKey
		err  error
	)
	if privKeyStr := cli.String("priv"); privKeyStr != "" {
		privBytes, err := hex.DecodeString(privKeyStr)
		if err != nil {
			return err
		}
		priv, pub = btcec.PrivKeyFromBytes(privBytes)

	} else {
		priv, err = btcec.NewPrivateKey()
		if err != nil {
			return err
		}

		pub = priv.PubKey()
	}

	fmt.Printf("Private Key: %x\nPublic Key: %x\n", priv.Serialize(),
		pub.SerializeCompressed())

	return nil
}

type onionSpec struct {
	SessionKey string         `json:"session_key"`
	Hops       []onionHopSpec `json:"hops"`
}

type onionHopSpec struct {
	PublicKey string `json:"pubkey"`
	Payload   string `json:"payload"`
}

func parseOnionSpec(spec onionSpec) (*sphinx.PaymentPath, *btcec.PrivateKey,
	error) {

	var err error
	sessionKeyBytes := []byte(defaultSessionKey)
	if spec.SessionKey != "" {
		sessionKeyBytes, err = hex.DecodeString(spec.SessionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode the "+
				"sessionKey %v: %v\n", spec.SessionKey, err)
		}
	}

	if len(sessionKeyBytes) != 32 {
		return nil, nil, fmt.Errorf("session priv key must be 32 " +
			"bytes long")
	}

	sessionKey, _ := btcec.PrivKeyFromBytes(sessionKeyBytes)

	var path sphinx.PaymentPath
	for i, hop := range spec.Hops {
		binKey, err := hex.DecodeString(hop.PublicKey)
		if err != nil {
			return nil, nil, err
		}

		pubkey, err := btcec.ParsePubKey(binKey)
		if err != nil {
			return nil, nil, err
		}

		path[i].NodePub = *pubkey

		payload, err := hex.DecodeString(hop.Payload)
		if err != nil {
			return nil, nil, err
		}

		hopPayload, err := sphinx.NewHopPayload(nil, payload)
		if err != nil {
			return nil, nil, err
		}

		path[i].HopPayload = hopPayload
	}

	return &path, sessionKey, nil
}

func generate(ctx *cli.Context) error {
	var spec onionSpec

	file := ctx.String("file")
	jsonSpec, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("unable to read JSON onion spec from "+
			"file %v: %v", file, err)
	}

	if err := json.Unmarshal(jsonSpec, &spec); err != nil {
		log.Fatalf("Unable to parse JSON onion spec: %v", err)
	}

	path, sessionKey, err := parseOnionSpec(spec)
	if err != nil {
		log.Fatalf("could not parse onion spec: %v", err)
	}

	msg, err := sphinx.NewOnionPacket(
		path, sessionKey, []byte(ctx.String("assoc_data")),
		sphinx.DeterministicPacketFiller,
	)
	if err != nil {
		log.Fatalf("Error creating message: %v", err)
	}

	w := bytes.NewBuffer([]byte{})
	err = msg.Encode(w)
	if err != nil {
		log.Fatalf("Error serializing message: %v", err)
	}

	fmt.Printf("%x\n", w.Bytes())
	return nil
}

func parse(ctx *cli.Context) error {
	sessionKeyBytes, err := hex.DecodeString(ctx.String("priv"))
	if err != nil {
		return err
	}

	if len(sessionKeyBytes) != 32 {
		return fmt.Errorf("session key must be 32 bytes")
	}
	sessionKey, _ := btcec.PrivKeyFromBytes(sessionKeyBytes)

	var blindingPoint *btcec.PublicKey
	if bpStr := ctx.String("blinding_point"); bpStr != "" {
		bpBytes, err := hex.DecodeString(bpStr)
		if err != nil {
			return err
		}

		blindingPoint, err = btcec.ParsePubKey(bpBytes)
		if err != nil {
			return err
		}
	}

	onion, err := hex.DecodeString(ctx.String("onion"))
	if err != nil {
		return err
	}

	var packet sphinx.OnionPacket
	err = packet.Decode(bytes.NewBuffer(onion))
	if err != nil {
		return err
	}

	s := sphinx.NewRouter(
		&sphinx.PrivKeyECDH{PrivKey: sessionKey},
		&chaincfg.TestNet3Params, sphinx.NewMemoryReplayLog(),
	)
	s.Start()
	defer s.Stop()

	p, err := s.ProcessOnionPacket(
		&packet, []byte(ctx.String("assocData")), 10, blindingPoint,
	)
	if err != nil {
		return err
	}

	w := bytes.NewBuffer([]byte{})
	err = p.NextPacket.Encode(w)

	if err != nil {
		log.Fatalf("Error serializing message: %v", err)
	}
	fmt.Printf("%x\n", w.Bytes())
	return nil
}

func nextBlindedPub(ctx *cli.Context) error {
	privKeyByte, err := hex.DecodeString(ctx.String("priv"))
	if err != nil {
		return err
	}
	if len(privKeyByte) != 32 {
		return fmt.Errorf("private key must be 32 bytes")
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyByte)

	pubKeyBytes, err := hex.DecodeString(ctx.String("pub"))
	if err != nil {
		return err
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return err
	}

	nextBlindedKey := sphinx.NextEphemeral(privKey, pubKey)
	fmt.Printf("%x\n", nextBlindedKey.SerializeCompressed())
	return nil
}

package sphinx

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

const routeBlindingHMACKey = "blinded_node_id"

// BlindedPath represents all the data that the creator of a blinded path must
// transmit to the builder of route that will send to this path.
type BlindedPath struct {
	// IntroductionPoint is the real node ID of the first hop in the blinded
	// path. The sender should be able to find this node in the network
	// graph and route to it.
	IntroductionPoint *btcec.PublicKey

	// BlindingPoint is the first ephemeral blinding point. This is the
	// point that the introduction node will use in order to create a shared
	// secret with the builder of the blinded route. This point will need
	// to be communicated to the introduction point by the sender in some
	// way.
	BlindingPoint *btcec.PublicKey

	// BlindedHops is a list of ordered blinded node IDs representing the
	// blinded route. Note that the first node ID is the blinded node ID of
	// the introduction point which does not strictly need to be transmitted
	// to the sender.
	BlindedHops []*btcec.PublicKey

	// EncryptedData is a list of encrypted_data byte arrays. Each entry
	// has been encrypted by the blinded route creator for a hop in the
	// blinded route.
	EncryptedData [][]byte
}

// BlindedPathHop represents a single hop in a blinded path. It is the data that
// the blinded route creator must provide about the hop in order for the
// BlindedPath to be constructed.
type BlindedPathHop struct {
	// NodePub is the real node ID of this hop.
	NodePub *btcec.PublicKey

	// Payload is the cleartext blob that should be encrypted for the hop.
	Payload []byte
}

// BuildBlindedPath creates a new BlindedPath from a list of BlindedPathHops and
// a session key.
func BuildBlindedPath(sessionKey *btcec.PrivateKey,
	paymentPath []*BlindedPathHop) (*BlindedPath, error) {

	if len(paymentPath) < 1 {
		return nil, fmt.Errorf("at least 1 hop required to create a " +
			"blinded path")
	}

	bp := BlindedPath{
		IntroductionPoint: paymentPath[0].NodePub,
		BlindingPoint:     sessionKey.PubKey(),
	}

	keys := make([]*btcec.PublicKey, len(paymentPath))
	for i, p := range paymentPath {
		keys[i] = p.NodePub
	}

	hopSharedSecrets, err := generateSharedSecrets(keys, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v",
			err)
	}

	for i, hop := range paymentPath {
		blindingFactorBytes := generateKey(
			routeBlindingHMACKey, &hopSharedSecrets[i],
		)

		var blindingFactor btcec.ModNScalar
		blindingFactor.SetBytes(&blindingFactorBytes)

		blindedNodeID := blindGroupElement(hop.NodePub, blindingFactor)
		bp.BlindedHops = append(bp.BlindedHops, blindedNodeID)

		rhoKey := generateKey("rho", &hopSharedSecrets[i])
		enc, err := chacha20polyEncrypt(rhoKey[:], hop.Payload)
		if err != nil {
			return nil, err
		}

		bp.EncryptedData = append(bp.EncryptedData, enc)
	}

	return &bp, nil
}

// DecryptBlindedData decrypts the data encrypted by the creator of the blinded
// route.
func DecryptBlindedData(priv *btcec.PrivateKey, ephemPub *btcec.PublicKey,
	encryptedData []byte) ([]byte, error) {

	p := PrivKeyECDH{PrivKey: priv}
	ss, err := p.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}

	ssHash := Hash256(ss)
	rho := generateKey("rho", &ssHash)
	return chacha20polyDecrypt(rho[:], encryptedData)
}

// NextEphemeral computes the next ephemeral key given the current ephemeral
// key and this node's private key.
func NextEphemeral(priv *btcec.PrivateKey,
	ephemPub *btcec.PublicKey) *btcec.PublicKey {

	p := PrivKeyECDH{PrivKey: priv}
	// Safe to ignore the error here as the PrivKeyECDH implementation of
	// the ECDH function does not return any errors.
	ss, _ := p.ECDH(ephemPub)

	blindingFactor := computeBlindingFactor(ephemPub, ss[:])
	nextEphem := blindGroupElement(ephemPub, blindingFactor)

	return nextEphem
}

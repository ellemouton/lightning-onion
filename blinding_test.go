package sphinx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

const (
	routeBlindingTestFileName      = "testdata/route-blinding-test.json"
	onionRouteBlindingTestFileName = "testdata/onion-route-blinding-test.json"
)

// TestBuildBlindedRoute tests BuildBlindedRoute and DecryptBlindedData against
// the spec test vectors.
func TestBlindBlindedRoute(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := ioutil.ReadFile(routeBlindingTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// blindingJsonTestCase struct defined below.
	testCase := &blindingJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))
	require.Len(t, testCase.Generate.Hops, 4)

	// buildPaymentPath is a helper closure used to convert hopData objects
	// into BlindedPathHop objects.
	buildPaymentPath := func(h []hopData) []*BlindedPathHop {
		path := make([]*BlindedPathHop, len(h))
		for i, hop := range h {
			nodeIDStr, _ := hex.DecodeString(hop.NodeID)
			nodeID, _ := btcec.ParsePubKey(nodeIDStr)
			payload, _ := hex.DecodeString(hop.EncodedTLVs)

			path[i] = &BlindedPathHop{
				NodePub: nodeID,
				Payload: payload,
			}
		}
		return path
	}

	// First, Eve will build a blinded path from Dave to herself.
	eveSessKey := privKeyFromString(testCase.Generate.Hops[2].SessionKey)
	eveDavePath := buildPaymentPath(testCase.Generate.Hops[2:])
	pathED, err := BuildBlindedPath(eveSessKey, eveDavePath)
	require.NoError(t, err)

	// At this point, Eve will give her blinded path to Bob who will then
	// build his own blinded route from himself to Carol. He will then
	// concatenate the two paths. Note that in his TLV for Carol, Bob will
	// add the `next_blinding_override` field which he will set to the
	// first blinding point in Eve's blinded route. This will indicate to
	// Carol that she should use this point for the next blinding key
	// instead of the next blinding key that she derives.
	bobCarolPath := buildPaymentPath(testCase.Generate.Hops[:2])
	bobSessKey := privKeyFromString(testCase.Generate.Hops[0].SessionKey)
	pathBC, err := BuildBlindedPath(bobSessKey, bobCarolPath)
	require.NoError(t, err)

	// Construct the concatenated path.
	path := &BlindedPath{
		IntroductionPoint: pathBC.IntroductionPoint,
		BlindingPoint:     pathBC.BlindingPoint,
		BlindedHops: append(pathBC.BlindedHops,
			pathED.BlindedHops...),
		EncryptedData: append(pathBC.EncryptedData,
			pathED.EncryptedData...),
	}

	// Check that the constructed path is equal to the test vector path.
	require.True(t, equalPubKeys(
		testCase.Route.IntroductionNodeID, path.IntroductionPoint,
	))
	require.True(t, equalPubKeys(
		testCase.Route.Blinding, path.BlindingPoint,
	))

	for i, hop := range testCase.Route.Hops {
		require.True(t, equalPubKeys(
			hop.BlindedNodeID, path.BlindedHops[i],
		))

		data, _ := hex.DecodeString(hop.EncryptedData)
		require.True(t, bytes.Equal(data, path.EncryptedData[i]))
	}

	// Assert that each hop is able to decode the encrypted data meant for
	// it.
	for i, hop := range testCase.Unblind.Hops {
		priv := privKeyFromString(hop.NodePrivKey)
		ephem := pubKeyFromString(hop.EphemeralPubKey)

		data, err := DecryptBlindedData(
			priv, ephem, path.EncryptedData[i],
		)
		require.NoError(t, err)

		decoded, _ := hex.DecodeString(hop.DecryptedData)
		require.True(t, bytes.Equal(data, decoded))

		require.True(t, equalPubKeys(
			hop.NextEphemeralPubKey, NextEphemeral(priv, ephem),
		))
	}
}

// TestOnionRouteBlinding tests that an onion packet can correctly be processed
// by a node in a blinded route.
func TestOnionRouteBlinding(t *testing.T) {
	t.Parallel()

	// First, we'll read out the raw Json file at the target location.
	jsonBytes, err := ioutil.ReadFile(onionRouteBlindingTestFileName)
	require.NoError(t, err)

	// Once we have the raw file, we'll unpack it into our
	// blindingJsonTestCase struct defined above.
	testCase := &onionBlindingJsonTestCase{}
	require.NoError(t, json.Unmarshal(jsonBytes, testCase))

	assoc, err := hex.DecodeString(testCase.Generate.AssocData)
	require.NoError(t, err)

	// Extract the original onion packet to be processed.
	onion, err := hex.DecodeString(testCase.Generate.Onion)
	require.NoError(t, err)

	onionBytes := bytes.NewReader(onion)
	onionPacket := &OnionPacket{}
	require.NoError(t, onionPacket.Decode(onionBytes))

	// peelOnion is a helper closure that can be used to set up a Router
	// and use it to process the given onion packet.
	peelOnion := func(key *btcec.PrivateKey, onionPkt *OnionPacket,
		blindingPoint *btcec.PublicKey) *ProcessedPacket {

		r := NewRouter(
			&PrivKeyECDH{PrivKey: key}, &chaincfg.MainNetParams,
			NewMemoryReplayLog(),
		)

		r.Start()
		defer r.Stop()

		res, err := r.ProcessOnionPacket(
			onionPacket, assoc, 10, blindingPoint,
		)
		require.NoError(t, err)
		return res
	}

	hops := testCase.Decrypt.Hops
	require.Len(t, hops, 5)

	// There are some things that the processor of the onion packet will
	// only be able to determine from the actual contents of the encrypted
	// data it receives. These things include the next_blinding_point for
	// the introduction point and the next_blinding_override. The decryption
	// of this data is dependent on the encoding chosen by higher layers.
	// The test uses TLVs. Since the extraction of this data is dependent
	// on layers outside the scope of this library, we provide handle these
	// cases manually for the sake of the test.
	var (
		introPointIndex = 2
		firstBlinding   = pubKeyFromString(hops[1].NextBlinding)

		concatIndex      = 3
		blindingOverride = pubKeyFromString(hops[2].NextBlinding)
	)

	var blindingPoint *btcec.PublicKey
	for i, hop := range testCase.Decrypt.Hops {
		buff := bytes.NewBuffer(nil)
		require.NoError(t, onionPacket.Encode(buff))
		require.Equal(t, hop.Onion, hex.EncodeToString(buff.Bytes()))

		priv := privKeyFromString(hop.NodePrivKey)

		if i == introPointIndex {
			blindingPoint = firstBlinding
		} else if i == concatIndex {
			blindingPoint = blindingOverride
		}

		processedPkt := peelOnion(priv, onionPacket, blindingPoint)

		if blindingPoint != nil {
			blindingPoint = NextEphemeral(priv, blindingPoint)
		}
		onionPacket = processedPkt.NextPacket
	}
}

type onionBlindingJsonTestCase struct {
	Comment  string            `json:"comment"`
	Generate generateOnionData `json:"generate"`
	Decrypt  decryptData       `json:"decrypt"`
}

type generateOnionData struct {
	Comment      string       `json:"comment"`
	SessionKey   string       `json:"session_key"`
	AssocData    string       `json:"associated_data"`
	BlindedRoute blindedRoute `json:"blinded_route"`
	FullRoute    fullRoute    `json:"full_route"`
	Onion        string       `json:"onion"`
}

type blindedRoute struct {
	Comment            string       `json:"comment"`
	IntroductionNodeID string       `json:"introduction_node_id"`
	Blinding           string       `json:"blinding"`
	Hops               []blindedHop `json:"hops"`
}

type fullRoute struct {
	Comment string             `json:"comment"`
	Hops    []fullRouteHopData `json:"hops"`
}

type fullRouteHopData struct {
	PubKey  string `json:"pubkey"`
	Payload string `json:"payload"`
}

type decryptData struct {
	Comment string        `json:"comment"`
	Hops    []decryptHops `json:"hops"`
}

type decryptHops struct {
	Onion        string `json:"onion"`
	NodePrivKey  string `json:"node_privkey"`
	NextBlinding string `json:"next_blinding""`
}

type blindingJsonTestCase struct {
	Comment  string       `json:"comment"`
	Generate generateData `json:"generate"`
	Route    routeData    `json:"route"`
	Unblind  unBlindData  `json:"unblind"`
}

type routeData struct {
	Comment            string       `json:"comment"`
	IntroductionNodeID string       `json:"introduction_node_id"`
	Blinding           string       `json:"blinding"`
	Hops               []blindedHop `json:"hops"`
}

type unBlindData struct {
	Comment string         `json:"comment"`
	Hops    []unBlindedHop `json:"hops"`
}

type generateData struct {
	Comment string    `json:"comment"`
	Hops    []hopData `json:"hops"`
}

type unBlindedHop struct {
	Alias                       string `json:"alias"`
	NodePrivKey                 string `json:"node_privkey"`
	EphemeralPubKey             string `json:"ephemeral_pubkey"`
	DecryptedData               string `json:"decrypted_data"`
	NextEphemeralPubKey         string `json:"next_ephemeral_pubkey"`
	NextEphemeralPubKeyOverride string `json:"next_ephemeral_pubkey_override"`
}

type hopData struct {
	Comment          string `json:"comment"`
	SessionKey       string `json:"session_key"`
	Alias            string `json:"alias"`
	NodeID           string `json:"node_id"`
	Tlvs             tlvs   `json:"tlvs"`
	EncodedTLVs      string `json:"encoded_tlvs"`
	EphemeralPrivKey string `json:"ephemeral_privkey"`
	EphemeralPubKey  string `json:"ephemeral_pubkey"`
	SharedSecret     string `json:"shared_secret"`
	Rho              string `json:"rho"`
	EncryptedData    string `json:"encrypted_data"`
	BlindedNodeID    string `json:"blinded_node_id"`
}

type tlvs struct {
	Padding              string `json:"padding"`
	ShortChannelID       string `json:"short_channel_id"`
	NextNodeID           string `json:"next_node_id"`
	NextBlindingOverride string `json:"next_blinding_override"`
	UnknownTag65001      string `json:"unknown_tag_65001"`
	UnknownTag65535      string `json:"unknown_tag_65535"`
}

type blindedHop struct {
	BlindedNodeID string `json:"blinded_node_id"`
	EncryptedData string `json:"encrypted_data"`
}

func equalPubKeys(pkStr string, pk *btcec.PublicKey) bool {
	return hex.EncodeToString(pk.SerializeCompressed()) == pkStr
}

func privKeyFromString(pkStr string) *btcec.PrivateKey {
	bytes, _ := hex.DecodeString(pkStr)
	key, _ := btcec.PrivKeyFromBytes(bytes)
	return key
}

func pubKeyFromString(pkStr string) *btcec.PublicKey {
	bytes, _ := hex.DecodeString(pkStr)
	key, _ := btcec.ParsePubKey(bytes)
	return key
}

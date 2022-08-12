package ciphersuite

import (
    "crypto/sha256"
    "errors"
    "fmt"
    "github.com/pion/dtls/v2"
    "github.com/pion/dtls/v2/pkg/protocol"
    "hash"
    "sync/atomic"

    "github.com/pion/dtls/v2/pkg/crypto/ciphersuite"
    "github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
    "github.com/pion/dtls/v2/pkg/crypto/prf"
    "github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

const (
    TLS_RSA_WITH_AES_128_GCM_SHA256 dtls.CipherSuiteID = 0x009c
)

var errCipherSuiteNotInit = &protocol.TemporaryError{Err: errors.New("CipherSuite has not been initialized")}

// TLSRsaWithAes128GcmSha256  represents a TLS_RSA_WITH_AES_128_GCM_SHA256 CipherSuite
type TLSRsaWithAes128GcmSha256 struct {
    gcm atomic.Value // *cryptoGCM
}

// CertificateType returns what type of certficate this CipherSuite exchanges
func (c *TLSRsaWithAes128GcmSha256) CertificateType() clientcertificate.Type {
    return clientcertificate.ECDSASign
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake
func (c *TLSRsaWithAes128GcmSha256) KeyExchangeAlgorithm() dtls.CipherSuiteKeyExchangeAlgorithm {
    return dtls.CipherSuiteKeyExchangeAlgorithmNone
}

// ECC uses Elliptic Curve Cryptography
func (c *TLSRsaWithAes128GcmSha256) ECC() bool {
    return false
}

// ID returns the ID of the CipherSuite
func (c *TLSRsaWithAes128GcmSha256) ID() dtls.CipherSuiteID {
    return TLS_RSA_WITH_AES_128_GCM_SHA256
}

func (c *TLSRsaWithAes128GcmSha256) String() string {
    return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
}

// HashFunc returns the hashing func for this CipherSuite
func (c *TLSRsaWithAes128GcmSha256) HashFunc() func() hash.Hash {
    return sha256.New
}

// AuthenticationType controls what authentication method is using during the handshake
func (c *TLSRsaWithAes128GcmSha256) AuthenticationType() dtls.CipherSuiteAuthenticationType {
    return dtls.CipherSuiteAuthenticationTypeCertificate
}

// IsInitialized returns if the CipherSuite has keying material and can
// encrypt/decrypt packets
func (c *TLSRsaWithAes128GcmSha256) IsInitialized() bool {
    return c.gcm.Load() != nil
}

func (c *TLSRsaWithAes128GcmSha256) init(masterSecret, clientRandom, serverRandom []byte, isClient bool, prfMacLen, prfKeyLen, prfIvLen int, hashFunc func() hash.Hash) error {
    keys, err := prf.GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, hashFunc)
    if err != nil {
        return err
    }

    var gcm *ciphersuite.GCM
    if isClient {
        gcm, err = ciphersuite.NewGCM(keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV)
    } else {
        gcm, err = ciphersuite.NewGCM(keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
    }
    c.gcm.Store(gcm)
    return err
}

// Init initializes the internal Cipher with keying material
func (c *TLSRsaWithAes128GcmSha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
    const (
        prfMacLen = 0
        prfKeyLen = 16
        prfIvLen  = 4
    )

    return c.init(masterSecret, clientRandom, serverRandom, isClient, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
}

// Encrypt encrypts a single TLS RecordLayer
func (c *TLSRsaWithAes128GcmSha256) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
    cipherSuite, ok := c.gcm.Load().(*ciphersuite.GCM)
    if !ok {
        return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
    }

    return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer
func (c *TLSRsaWithAes128GcmSha256) Decrypt(raw []byte) ([]byte, error) {
    cipherSuite, ok := c.gcm.Load().(*ciphersuite.GCM)
    if !ok {
        return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
    }

    return cipherSuite.Decrypt(raw)
}

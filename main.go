package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/kyprizel/u2fg"
	"io"
	"io/ioutil"
	"log"
	"math/big"
)

const (
	minPacketLen   = 4
	headerLen      = minPacketLen + 3
	challengeLen   = 32
	applicationLen = 32

	cmdRegister     = 1
	cmdAuthenticate = 2
	cmdVersion      = 3

	statusNoError                = 0x9000
	statusWrongLength            = 0x6700
	statusInvalidData            = 0x6984
	statusConditionsNotSatisfied = 0x6985
	statusWrongData              = 0x6a80
	statusInsNotSupported        = 0x6d00

	tupRequired = 1 // Test of User Presence required
	tupConsume  = 2 // Consume a Test of User Presence
	tupTestOnly = 4 // Check valid key handle only, no test of user presence required

	authEnforce   = tupRequired | tupConsume
	authCheckOnly = tupRequired | tupConsume | tupTestOnly
)

type Response struct {
	Data   []byte
	Status uint16
}

type dsaSignature struct {
	R, S *big.Int
}

type U2FToken interface {
	NewHandleByPrivateKey(eccKey *ecdsa.PrivateKey) ([]byte, error)
	GetPrivateKeyByHandle(handle []byte) (*ecdsa.PrivateKey, error)
	CheckUserPrescense() bool
	Wink()
	GetCounter()
}

type U2FProcessor struct {
	DevicePath string
	AESKey     []byte
	Counter    uint32

	AttestationCertificate []byte
	privKey                *ecdsa.PrivateKey
}

func (h *U2FProcessor) CheckUserPrescense() bool {
	/* User prescense SHOULD be checked */
	/* GPIO or INTERLOCK can be used */
	return false
}

func (h *U2FProcessor) Wink() {
	log.Printf("Wink! Wink!")
	return
}

func (h *U2FProcessor) GetCounter() uint32 {
	/* Counter needs to be stored in persistent storage */
	h.Counter += 1
	log.Printf("Counter: %d", h.Counter)
	return h.Counter
}

func (h *U2FProcessor) ProcessMessage(packet []byte) []byte {
	r, err := h.doProcessMessage(packet)
	if err != nil {
		log.Printf("Msg handling error (%v)", err)
	}

	buf := make([]byte, len(r.Data)+2)
	n := copy(buf[0:], r.Data)

	buf[n] = uint8(r.Status >> 8)
	buf[n+1] = uint8(r.Status & 0xff)
	return buf
}

func (h *U2FProcessor) GetPrivateKeyByHandle(handle []byte) (*ecdsa.PrivateKey, error) {
	/* We expect nonce and at least one AES block */
	if len(handle) < 28 {
		return nil, fmt.Errorf("u2femu: invalid Authenticate params (handle len %d)", len(handle))
	}

	block, err := aes.NewCipher(h.AESKey)
	if err != nil {
		return nil, fmt.Errorf("u2femu: AES init error")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("u2femu: AES init error")
	}

	plaintext, err := aesgcm.Open(nil, handle[:12], handle[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("u2femu: AES decrypt error")
	}

	privKey, err := x509.ParseECPrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("u2femu: invalid Authenticate params (ECC)")
	}

	return privKey, nil
}

func (h *U2FProcessor) NewHandleByPrivateKey(eccKey *ecdsa.PrivateKey) ([]byte, error) {
	/* To be stateless we just wrap a private key with AES-GCM */
	/* You can implement your own wrapper with k-v storage etc */

	block, err := aes.NewCipher(h.AESKey)
	if err != nil {
		return nil, fmt.Errorf("u2femu: AES init error")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("u2femu: GCM init error")
	}

	/* XXX: prevent nonce reuse! */
	nonce := make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("u2femu: error reading Nonce")
	}

	privateKey, err := x509.MarshalECPrivateKey(eccKey)
	if err != nil {
		return nil, fmt.Errorf("u2femu: error reading Nonce")
	}

	ciphertext := aesgcm.Seal(nil, nonce, privateKey, nil)

	handle := make([]byte, 12)
	copy(handle[0:], nonce)
	handle = append(handle, ciphertext...)
	return handle, nil
}

func doSignWrap(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, priv, hash)
	if err != nil {
		return nil, fmt.Errorf("u2femu: ecdsa sign error")
	}

	dsaSig := dsaSignature{R: r, S: s}
	return asn1.Marshal(dsaSig)
}

func (h *U2FProcessor) doProcessMessage(packet []byte) (Response, error) {
	if len(packet) < minPacketLen {
		r := Response{Data: nil, Status: statusWrongData}
		return r, fmt.Errorf("u2femu: message is too short, only received %d bytes", len(packet))
	}
	if packet[0] != 0 {
		r := Response{Data: nil, Status: statusWrongData}
		return r, fmt.Errorf("u2femu: wrong CLA")
	}

	cmd := packet[1]
	param1 := packet[2]
	switch cmd {
	case cmdVersion:
		log.Printf("u2femu: Version command received")
		r := Response{Data: []byte("U2F_V2"), Status: statusNoError}
		return r, nil

	case cmdRegister:
		log.Printf("u2femu: Register command received")

		if len(packet) < headerLen {
			r := Response{Data: nil, Status: statusWrongLength}
			return r, fmt.Errorf("u2femu: invalid Register params (data len)")
		}
		dataLen := uint32(uint8(packet[6]) | uint8(packet[5]<<8) | uint8(packet[4]<<16))
		if dataLen != 64 || len(packet[6:]) < 64 {
			r := Response{Data: nil, Status: statusWrongLength}
			return r, fmt.Errorf("u2femu: invalid Register params (data len != 64)")
		}
		if param1 != authEnforce {
			r := Response{Data: nil, Status: statusConditionsNotSatisfied}
			return r, fmt.Errorf("u2femu: user prescense required")
		}
		if !h.CheckUserPrescense() {
			r := Response{Data: nil, Status: statusConditionsNotSatisfied}
			return r, fmt.Errorf("u2femu: user prescense required")
		}

		/* challenge is always 32 bytes */
		challenge := packet[headerLen : headerLen+challengeLen]

		/* application is always 32 bytes */
		application := packet[headerLen+challengeLen : headerLen+challengeLen+applicationLen]

		/* ECC Key generation goes here */
		eccCurve := elliptic.P256()
		eccKey := new(ecdsa.PrivateKey)
		eccKey, err := ecdsa.GenerateKey(eccCurve, rand.Reader)
		if err != nil {
			r := Response{Data: nil, Status: statusWrongData}
			return r, fmt.Errorf("u2femu: key generation error")
		}

		pub := eccKey.PublicKey
		publicKey := elliptic.Marshal(pub.Curve, pub.X, pub.Y)

		/* Handle generation goes here */
		handle, err := h.NewHandleByPrivateKey(eccKey)
		if err != nil {
			r := Response{Data: nil, Status: statusWrongData}
			return r, err
		}

		hasher := sha256.New()
		hasher.Write([]byte("\x00"))
		hasher.Write(application)
		hasher.Write(challenge)
		hasher.Write(handle)
		hasher.Write(publicKey)

		signature, err := doSignWrap(rand.Reader, h.privKey, hasher.Sum(nil))
		if err != nil {
			r := Response{Data: nil, Status: statusWrongData}
			return r, fmt.Errorf("u2femu: asn1 error")
		}

		buf := []byte{0x05}
		buf = append(buf, publicKey...)
		buf = append(buf, []byte{uint8(len(handle))}...)
		buf = append(buf, handle...)
		buf = append(buf, h.AttestationCertificate...)
		buf = append(buf, signature...)
		r := Response{Data: buf, Status: statusNoError}
		return r, nil

	case cmdAuthenticate:
		log.Printf("u2femu: Authenticate command received")

		userPrescenseByte := 0x00
		if param1 != authCheckOnly && param1 != authEnforce {
			r := Response{Data: nil, Status: statusWrongData}
			return r, fmt.Errorf("u2femu: invalid Authenticate params")
		}
		if param1 == authEnforce {
			if !h.CheckUserPrescense() {
				r := Response{Data: nil, Status: statusConditionsNotSatisfied}
				return r, fmt.Errorf("u2femu: user prescense required")
			}
			userPrescenseByte = 0x01
		}

		if len(packet) < headerLen {
			r := Response{Data: nil, Status: statusWrongLength}
			return r, fmt.Errorf("u2femu: invalid Authenticate params (data len)")
		}
		dataLen := uint32(uint8(packet[6]) | uint8(packet[5]<<8) | uint8(packet[4]<<16))
		if dataLen < 65 {
			r := Response{Data: nil, Status: statusWrongLength}
			return r, fmt.Errorf("u2femu: invalid Authenticate params (data len < 65)")
		}

		/* challenge is always 32 bytes len */
		challenge := packet[headerLen : headerLen+challengeLen]

		/* application is always 32 bytes len */
		application := packet[headerLen+challengeLen : headerLen+challengeLen+applicationLen]

		handleLen := int(packet[headerLen+len(challenge)+len(application)])
		if handleLen+challengeLen+applicationLen > int(dataLen) {
			r := Response{Data: nil, Status: statusWrongLength}
			return r, fmt.Errorf("u2femu: invalid Authenticate handleLen (%d)", handleLen)
		}

		handle := packet[headerLen+challengeLen+applicationLen+1 : headerLen+challengeLen+applicationLen+1+handleLen]

		privKey, err := h.GetPrivateKeyByHandle(handle)
		if err != nil {
			r := Response{Data: nil, Status: statusWrongData}
			return r, err
		}

		/* it is check-only message, do not respond with signature */
		if param1 != authEnforce {
			r := Response{Data: nil, Status: statusConditionsNotSatisfied}
			return r, fmt.Errorf("u2femu: user prescense required")
		}

		counter := h.GetCounter()

		signatureInput := make([]byte, len(application)+1+4)
		n := copy(signatureInput[0:], application)
		signatureInput[n] = uint8(userPrescenseByte)
		binary.BigEndian.PutUint32(signatureInput[n+1:], counter)
		signatureInput = append(signatureInput, challenge...)

		hasher := sha256.New()
		hasher.Write(signatureInput)

		signature, err := doSignWrap(rand.Reader, privKey, hasher.Sum(nil))
		if err != nil {
			r := Response{Data: nil, Status: statusWrongData}
			return r, fmt.Errorf("u2femu: asn1 error")
		}

		buf := make([]byte, 1+4)
		buf[0] = uint8(userPrescenseByte)
		binary.BigEndian.PutUint32(buf[1:], counter)
		buf = append(buf, signature...)
		r := Response{Data: buf, Status: statusNoError}
		return r, nil
	}

	r := Response{Data: nil, Status: statusInsNotSupported}
	return r, fmt.Errorf("u2femu: unknown data")
}

func main() {
	certPEMData, err := ioutil.ReadFile("attestation-cert.pem")
	if err != nil {
		log.Fatal("Can't read attestation certificate.")
	}

	block, _ := pem.Decode(certPEMData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode PEM block containing attestation certificate (%v)", block.Type)
	}

	certKey, err := ioutil.ReadFile("attestation-key.pem")
	if err != nil {
		log.Fatal("Can't read attestation key.")
	}

	privKeyBlock, _ := pem.Decode(certKey)
	if privKeyBlock == nil || privKeyBlock.Type != "EC PRIVATE KEY" {
		log.Fatal("Failed to decode PEM block containing attestation private key (%v)", privKeyBlock.Type)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to parse attestation private key (%v)", err)
	}

	h := &U2FProcessor{DevicePath: "/dev/hidg0", AESKey: []byte("AES256-KEY-MOVE-ME-TO-CONFIG-123"),
		Counter: 0, AttestationCertificate: block.Bytes, privKey: privKey}

	d, err := u2fg.Init(h.DevicePath)
	if err != nil {
		log.Fatal(err)
	}
	d.Run(h)
	log.Printf("ok")
	d.Close()
}

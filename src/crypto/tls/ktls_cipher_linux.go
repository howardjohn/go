// +build linux

package tls

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"
)

const (
	kTLS_CIPHER_AES_GCM_128              = 51
	kTLS_CIPHER_AES_GCM_128_IV_SIZE      = 8
	kTLS_CIPHER_AES_GCM_128_KEY_SIZE     = 16
	kTLS_CIPHER_AES_GCM_128_SALT_SIZE    = 4
	kTLS_CIPHER_AES_GCM_128_TAG_SIZE     = 16
	kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE = 8

	kTLS_CIPHER_AES_GCM_256              = 52
	kTLS_CIPHER_AES_GCM_256_IV_SIZE      = 8
	kTLS_CIPHER_AES_GCM_256_KEY_SIZE     = 32
	kTLS_CIPHER_AES_GCM_256_SALT_SIZE    = 4
	kTLS_CIPHER_AES_GCM_256_TAG_SIZE     = 16
	kTLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE = 8

	kTLS_CIPHER_AES_CCM_128              = 53
	kTLS_CIPHER_AES_CCM_128_IV_SIZE      = 8
	kTLS_CIPHER_AES_CCM_128_KEY_SIZE     = 16
	kTLS_CIPHER_AES_CCM_128_SALT_SIZE    = 4
	kTLS_CIPHER_AES_CCM_128_TAG_SIZE     = 16
	kTLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE = 8

	kTLS_CIPHER_CHACHA20_POLY1305              = 54
	kTLS_CIPHER_CHACHA20_POLY1305_IV_SIZE      = 12
	kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE     = 32
	kTLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE    = 0
	kTLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE     = 16
	kTLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE = 8
)

type kTLSCryptoInfo struct {
	version    uint16
	cipherType uint16
}

type kTLSCryptoInfoAESGCM128 struct {
	info   kTLSCryptoInfo
	iv     [kTLS_CIPHER_AES_GCM_128_IV_SIZE]byte
	key    [kTLS_CIPHER_AES_GCM_128_KEY_SIZE]byte
	salt   [kTLS_CIPHER_AES_GCM_128_SALT_SIZE]byte
	recSeq [kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE]byte
}

type kTLSCryptoInfoAESGCM256 struct {
	info   kTLSCryptoInfo
	iv     [kTLS_CIPHER_AES_GCM_256_IV_SIZE]byte
	key    [kTLS_CIPHER_AES_GCM_256_KEY_SIZE]byte
	salt   [kTLS_CIPHER_AES_GCM_256_SALT_SIZE]byte
	recSeq [kTLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE]byte
}

type kTLSCryptoInfoAESCCM128 struct {
	info   kTLSCryptoInfo
	iv     [kTLS_CIPHER_AES_CCM_128_IV_SIZE]byte
	key    [kTLS_CIPHER_AES_CCM_128_KEY_SIZE]byte
	salt   [kTLS_CIPHER_AES_CCM_128_SALT_SIZE]byte
	recSeq [kTLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE]byte
}

type kTLSCryptoInfoCHACHA20POLY1305 struct {
	info   kTLSCryptoInfo
	iv     [kTLS_CIPHER_CHACHA20_POLY1305_IV_SIZE]byte
	key    [kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE]byte
	salt   [kTLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE]byte
	recSeq [kTLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE]byte
}

const (
	kTLSCryptoInfoSize_AES_GCM_128 = 2 + 2 + kTLS_CIPHER_AES_GCM_128_IV_SIZE + kTLS_CIPHER_AES_GCM_128_KEY_SIZE +
		kTLS_CIPHER_AES_GCM_128_SALT_SIZE + kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE

	kTLSCryptoInfoSize_AES_GCM_256 = 2 + 2 + kTLS_CIPHER_AES_GCM_256_IV_SIZE + kTLS_CIPHER_AES_GCM_256_KEY_SIZE +
		kTLS_CIPHER_AES_GCM_256_SALT_SIZE + kTLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE

	kTLSCryptoInfoSize_AES_CCM_128 = 2 + 2 + kTLS_CIPHER_AES_CCM_128_IV_SIZE + kTLS_CIPHER_AES_CCM_128_KEY_SIZE +
		kTLS_CIPHER_AES_CCM_128_SALT_SIZE + kTLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE

	kTLSCryptoInfoSize_CHACHA20_POLY1305 = 2 + 2 + kTLS_CIPHER_CHACHA20_POLY1305_IV_SIZE + kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE +
		kTLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE + kTLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE
)

func ktlsEnableAES(
	c *Conn,
	version uint16,
	enableFunc func(c *net.TCPConn, version uint16, opt int, skip bool, key, iv, seq []byte) error,
	keyLen int,
	inKey, outKey, inIV, outIV []byte) error {
	var ulpEnabled bool
	if len(outKey) == keyLen {
		if tcpConn, ok := c.conn.(*net.TCPConn); ok {
			if err := enableFunc(tcpConn, version, TLS_TX, ulpEnabled, outKey, outIV[:], c.out.seq[:]); err != nil {
				log.Println("kTLS: TLS_TX error enabling:", err)
				return err
			}
			ulpEnabled = true
			log.Println("kTLS: TLS_TX enabled")
			c.out.cipher = kTLSCipher{}
		} else {
			log.Println("kTLS: TLS_TX unsupported connection type")
		}
	} else {
		log.Println("kTLS: TLS_TX unsupported key length")
	}
	if !kTLSSupportRX {
		return nil
	}
	if len(inKey) == keyLen {
		if tcpConn, ok := c.conn.(*net.TCPConn); ok {
			if err := enableFunc(tcpConn, version, TLS_RX, ulpEnabled, inKey, inIV[:], c.in.seq[:]); err != nil {
				log.Println("kTLS: TLS_RX error enabling:", err)
				return err
			}
			log.Println("kTLS: TLS_RX enabled")
			c.in.cipher = kTLSCipher{}
		} else {
			log.Println("kTLS: TLS_RX unsupported connection type")
		}
	} else {
		log.Println("kTLS: TLS_TX unsupported key length")
	}
	return nil
}

func ktlsEnableCHACHA20(c *Conn, version uint16, inKey, outKey, inIV, outIV []byte) error {
	var ulpEnabled bool
	if tcpConn, ok := c.conn.(*net.TCPConn); ok {
		err := ktlsEnableCHACHA20POLY1305(tcpConn, version, TLS_TX, ulpEnabled, outKey, outIV, c.out.seq[:])
		if err != nil {
			log.Println("kTLS: TLS_TX error enabling:", err)
			return err
		}
		ulpEnabled = true
		log.Println("kTLS: TLS_TX enabled")
		c.out.cipher = kTLSCipher{}
	} else {
		log.Println("kTLS: TLS_TX unsupported connection type")
	}
	if !kTLSSupportRX {
		return nil
	}
	if tcpConn, ok := c.conn.(*net.TCPConn); ok {
		err := ktlsEnableCHACHA20POLY1305(tcpConn, version, TLS_RX, ulpEnabled, inKey[:], inIV[:], c.in.seq[:])
		if err != nil {
			log.Println("kTLS: TLS_RX error enabling:", err)
			return err
		}
		ulpEnabled = true
		log.Println("kTLS: TLS_RX enabled")
		c.in.cipher = kTLSCipher{}
	} else {
		log.Println("kTLS: TLS_RX unsupported connection type")
	}

	return nil
}

func ktlsEnableAES128GCM(c *net.TCPConn, version uint16, opt int, skip bool, key, iv, seq []byte) error {
	if len(key) != kTLS_CIPHER_AES_GCM_128_KEY_SIZE {
		return fmt.Errorf("kTLS: wrong key length, desired: %d, actual: %d",
			kTLS_CIPHER_AES_GCM_128_KEY_SIZE, len(key))
	}
	//if len(iv) != kTLS_CIPHER_AES_GCM_128_IV_SIZE {
	//	return fmt.Errorf("kTLS: wrong iv length, desired: %d, actual: %d",
	//		kTLS_CIPHER_AES_GCM_128_IV_SIZE, len(iv))
	//}
	if len(seq) != kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE {
		return fmt.Errorf("kTLS: wrong seq length, desired: %d, actual: %d",
			kTLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE, len(seq))
	}

	cryptoInfo := kTLSCryptoInfoAESGCM128{
		info: kTLSCryptoInfo{
			version:    version,
			cipherType: kTLS_CIPHER_AES_GCM_128,
		},
	}

	log.Printf("\nkey: %x\niv: %x\nseq: %x", key, iv, seq)
	copy(cryptoInfo.key[:], key)
	copy(cryptoInfo.salt[:], iv)
	// TODO https://github.com/FiloSottile/go/blob/filippo%2FkTLS/src/crypto/tls/ktls.go#L73
	// the PoC of FiloSottile here is copy(cryptoInfo.iv[:], seq)
	copy(cryptoInfo.iv[:], seq)
	copy(cryptoInfo.recSeq[:], seq)

	// Assert padding isn't introduced by alignment requirements.
	if unsafe.Sizeof(cryptoInfo) != kTLSCryptoInfoSize_AES_GCM_128 {
		return fmt.Errorf("kTLS: wrong cryptoInfo size, desired: %d, actual: %d",
			kTLSCryptoInfoSize_AES_GCM_128, unsafe.Sizeof(cryptoInfo))
	}

	rwc, err := c.SyscallConn()
	if err != nil {
		return err
	}

	var err0 error
	err = rwc.Control(func(fd uintptr) {
		if !skip {
			err0 = syscall.SetsockoptString(int(fd), syscall.SOL_TCP, TCP_ULP, "tls")
			if err0 != nil {
				log.Println("kTLS: setsockopt(SOL_TCP, TCP_ULP) failed:", err0)
			}
		}
		err0 = syscall.SetsockoptString(int(fd), SOL_TLS, opt,
			string((*[kTLSCryptoInfoSize_AES_GCM_128]byte)(unsafe.Pointer(&cryptoInfo))[:]))
		if err0 != nil {
			log.Printf("kTLS: setsockopt(SOL_TLS, %d) failed: %s", opt, err0)
			return
		}
	})
	if err == nil {
		err = err0
	}
	return err
}

func ktlsEnableAES256GCM(c *net.TCPConn, version uint16, opt int, skip bool, key, iv, seq []byte) error {
	if len(key) != kTLS_CIPHER_AES_GCM_256_KEY_SIZE {
		return fmt.Errorf("kTLS: wrong key length, desired: %d, actual: %d",
			kTLS_CIPHER_AES_GCM_256_KEY_SIZE, len(key))
	}
	//if len(iv) != kTLS_CIPHER_AES_GCM_256_IV_SIZE {
	//	return fmt.Errorf("kTLS: wrong iv length, desired: %d, actual: %d",
	//		kTLS_CIPHER_AES_GCM_256_IV_SIZE, len(iv))
	//}
	if len(seq) != kTLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE {
		return fmt.Errorf("kTLS: wrong seq length, desired: %d, actual: %d",
			kTLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE, len(seq))
	}

	cryptoInfo := kTLSCryptoInfoAESGCM256{
		info: kTLSCryptoInfo{
			version:    version,
			cipherType: kTLS_CIPHER_AES_GCM_256,
		},
	}
	log.Printf("key: %x\niv: %x\n seq: %x", key, iv, seq)
	copy(cryptoInfo.key[:], key)
	copy(cryptoInfo.salt[:], iv)
	// TODO https://github.com/FiloSottile/go/blob/filippo%2FkTLS/src/crypto/tls/ktls.go#L73
	// the PoC of FiloSottile here is copy(cryptoInfo.iv[:], seq)
	copy(cryptoInfo.iv[:], seq)
	copy(cryptoInfo.recSeq[:], seq)

	// Assert padding isn't introduced by alignment requirements.
	if unsafe.Sizeof(cryptoInfo) != kTLSCryptoInfoSize_AES_GCM_256 {
		return fmt.Errorf("kTLS: wrong cryptoInfo size, desired: %d, actual: %d",
			kTLSCryptoInfoSize_AES_GCM_256, unsafe.Sizeof(cryptoInfo))
	}

	rwc, err := c.SyscallConn()
	if err != nil {
		return err
	}

	var err0 error
	err = rwc.Control(func(fd uintptr) {
		if !skip {
			err0 = syscall.SetsockoptString(int(fd), syscall.SOL_TCP, TCP_ULP, "tls")
			if err0 != nil {
				log.Println("kTLS: setsockopt(SOL_TCP, TCP_ULP) failed:", err0)
				return
			}
		}
		err0 = syscall.SetsockoptString(int(fd), SOL_TLS, opt,
			string((*[kTLSCryptoInfoSize_AES_GCM_256]byte)(unsafe.Pointer(&cryptoInfo))[:]))
		if err0 != nil {
			log.Printf("kTLS: setsockopt(SOL_TLS, %d) failed: %s", opt, err0)
			return
		}
	})
	if err == nil {
		err = err0
	}
	return err
}

func ktlsEnableCHACHA20POLY1305(c *net.TCPConn, version uint16, opt int, skip bool, key, iv, seq []byte) error {
	if len(key) != kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE {
		return fmt.Errorf("kTLS: wrong key length, desired: %d, actual: %d",
			kTLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE, len(key))
	}
	if len(seq) != kTLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE {
		return fmt.Errorf("kTLS: wrong seq length, desired: %d, actual: %d",
			kTLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE, len(seq))
	}

	cryptoInfo := kTLSCryptoInfoCHACHA20POLY1305{
		info: kTLSCryptoInfo{
			version:    version,
			cipherType: kTLS_CIPHER_CHACHA20_POLY1305,
		},
	}
	copy(cryptoInfo.key[:], key)
	copy(cryptoInfo.iv[:], iv)
	copy(cryptoInfo.recSeq[:], seq)

	// Assert padding isn't introduced by alignment requirements.
	if unsafe.Sizeof(cryptoInfo) != kTLSCryptoInfoSize_CHACHA20_POLY1305 {
		return fmt.Errorf("kTLS: wrong cryptoInfo size, desired: %d, actual: %d",
			kTLSCryptoInfoSize_CHACHA20_POLY1305, unsafe.Sizeof(cryptoInfo))
	}

	rwc, err := c.SyscallConn()
	if err != nil {
		return err
	}

	var err0 error
	err = rwc.Control(func(fd uintptr) {
		if !skip {
			err0 = syscall.SetsockoptString(int(fd), syscall.SOL_TCP, TCP_ULP, "tls")
			if err0 != nil {
				log.Println("kTLS: setsockopt(SOL_TCP, TCP_ULP) failed:", err0)
				return
			}
		}
		err0 = syscall.SetsockoptString(int(fd), SOL_TLS, opt,
			string((*[kTLSCryptoInfoSize_CHACHA20_POLY1305]byte)(unsafe.Pointer(&cryptoInfo))[:]))
		if err0 != nil {
			log.Printf("kTLS: setsockopt(SOL_TLS, %d) failed: %s", opt, err0)
			return
		}
	})
	if err == nil {
		err = err0
	}
	return err
}

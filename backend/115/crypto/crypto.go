package crypto

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"unsafe"
)

//#cgo CFLAGS: -I.
//#cgo LDFLAGS: -L. -lencode115
//
//#include "encode115.h"
import "C"

type DigestResult struct {
	Size    int64
	PreId   string
	QuickId string
	MD5     string
}

var (
	hashPreSize int64 = 128 * 1024
)

func init() {
	C.m115_edinit()
	C.m115_xorinit()
}

func GenerateKey() string {
	var key [16]byte
	_, _ = io.ReadFull(rand.Reader, key[:])
	return hex.EncodeToString(key[:])
}

func Encode(input []byte, key []byte) ([]byte, error) {
	out := make([]byte, 2048)
	outlen := int32(-1)

	C.m115_encode((*C.uchar)(unsafe.Pointer(&input[0])),
		C.uint(len(input)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uint)(unsafe.Pointer(&outlen)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(nil)))

	return out[:outlen], nil
}

func Decode(input []byte, key []byte) ([]byte, error) {
	out := make([]byte, 2048)
	outlen := int32(-1)
	keyout := make([]byte, 128)

	C.m115_decode((*C.uchar)(unsafe.Pointer(&input[0])),
		C.uint(len(input)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uint)(unsafe.Pointer(&outlen)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&keyout[0])))

	return out[:outlen], nil
}

func Digest(r io.Reader, result *DigestResult) error {
	hs, hm := sha1.New(), md5.New()
	w := io.MultiWriter(hs, hm)
	// Calculate SHA1 hash of first 128K, which is used as PreId
	var err error
	result.Size, err = io.CopyN(w, r, hashPreSize)
	if err != nil && err != io.EOF {
		return err
	}
	result.PreId = strings.ToUpper(hex.EncodeToString(hs.Sum(nil)))
	// Write remain data.
	if err == nil {
		var n int64
		if n, err = io.Copy(w, r); err != nil {
			return err
		}
		result.Size += n
		result.QuickId = strings.ToUpper(hex.EncodeToString(hs.Sum(nil)))
	} else {
		result.QuickId = result.PreId
	}
	result.MD5 = base64.StdEncoding.EncodeToString(hm.Sum(nil))
	return nil
}

func UploadSignature(userID int64, userKey string, targetID string, fileID string) string {
	digester := sha1.New()
	digester.Write([]byte(strconv.FormatInt(userID, 10)))
	digester.Write([]byte(fileID))
	digester.Write([]byte(fileID))
	digester.Write([]byte(targetID))
	digester.Write([]byte("0"))
	h := hex.EncodeToString(digester.Sum(nil))
	digester.Reset()
	digester.Write([]byte(userKey))
	digester.Write([]byte(h))
	digester.Write([]byte("000000"))
	return strings.ToUpper(hex.EncodeToString(digester.Sum(nil)))
}

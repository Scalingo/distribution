// Package middleware - encrypt and decrypt dynamically blob conttent
//
package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/docker/distribution/context"

	storagedriver "github.com/docker/distribution/registry/storage/driver"
	storagemiddleware "github.com/docker/distribution/registry/storage/driver/middleware"
)

type encryptStorageMiddleware struct {
	storagedriver.StorageDriver
	block cipher.Block
	iv    []byte
}

var _ storagedriver.StorageDriver = &encryptStorageMiddleware{}

// newEncryptStorageMiddleware constructs and returns a new Encryption middleware
// Required options: key, iv
func newEncryptStorageMiddleware(storageDriver storagedriver.StorageDriver, options map[string]interface{}) (storagedriver.StorageDriver, error) {
	key, ok := options["key"]
	if !ok {
		return nil, fmt.Errorf("no key provided")
	}
	sKey, ok := key.(string)
	if !ok {
		return nil, fmt.Errorf("key must be a string")
	}
	rawKey, err := base64.StdEncoding.DecodeString(sKey)
	if err != nil {
		return nil, fmt.Errorf("key is not encoded in valid base64")
	}
	if len(rawKey) > 32 {
		rawKey = rawKey[:32]
	}

	iv, ok := options["iv"]
	if !ok {
		return nil, fmt.Errorf("no iv provided")
	}
	sIV, ok := iv.(string)
	if !ok {
		return nil, fmt.Errorf("iv must be a string")
	}
	rawIV, err := base64.StdEncoding.DecodeString(sIV)
	if err != nil {
		return nil, fmt.Errorf("iv is not encoded in valid base64")
	}
	if len(rawIV) > aes.BlockSize {
		rawIV = rawIV[:aes.BlockSize]
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("fail to create aes block from key: %v", err)
	}

	return &encryptStorageMiddleware{
		StorageDriver: storageDriver,
		block:         block,
		iv:            []byte(rawIV),
	}, nil
}

func (m *encryptStorageMiddleware) GetContent(ctx context.Context, path string) ([]byte, error) {
	content, err := m.StorageDriver.GetContent(ctx, path)
	if err != nil {
		return nil, err
	}

	unencryptedContent := make([]byte, 0, aes.BlockSize+len(content))
	m.block.Decrypt(unencryptedContent, content)
	return unencryptedContent[aes.BlockSize:], nil
}

func (m *encryptStorageMiddleware) PutContent(ctx context.Context, path string, content []byte) error {
	encryptedContent := make([]byte, 0, aes.BlockSize+len(content))
	m.block.Encrypt(encryptedContent, append(m.iv, content...))
	return m.StorageDriver.PutContent(ctx, path, encryptedContent)
}

func (m *encryptStorageMiddleware) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	rc, err := m.StorageDriver.Reader(ctx, path, offset)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(m.block, m.iv)
	reader := streamReadCloser{cipher.StreamReader{S: stream, R: rc}}
	return reader, nil
}

func (m *encryptStorageMiddleware) Writer(ctx context.Context, path string, append bool) (storagedriver.FileWriter, error) {
	realWriter, err := m.StorageDriver.Writer(ctx, path, append)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(m.block, m.iv)
	writer := cipher.StreamWriter{S: stream, W: realWriter}

	return &encryptedWriter{writer}, nil
}

type streamReadCloser struct {
	cipher.StreamReader
}

func (s streamReadCloser) Close() error {
	return s.R.(io.Closer).Close()
}

type encryptedWriter struct {
	cipher.StreamWriter
}

func (w encryptedWriter) Close() error {
	return w.W.(storagedriver.FileWriter).Close()
}
func (w encryptedWriter) Size() int64 {
	return w.W.(storagedriver.FileWriter).Size()
}
func (w encryptedWriter) Cancel() error {
	return w.W.(storagedriver.FileWriter).Cancel()
}
func (w encryptedWriter) Commit() error {
	return w.W.(storagedriver.FileWriter).Commit()
}

// init registers the encrypt middleware backend.
func init() {
	fmt.Println("GRGREGERGER")
	storagemiddleware.Register("encrypt", storagemiddleware.InitFunc(newEncryptStorageMiddleware))
}

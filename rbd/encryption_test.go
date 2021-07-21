// +build !octopus,!nautilus

package rbd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionFormat(t *testing.T) {
	conn := radosConnect(t)

	poolname := GetUUID()
	err := conn.MakePool(poolname)
	assert.NoError(t, err)

	ioctx, err := conn.OpenIOContext(poolname)
	require.NoError(t, err)

	name := GetUUID()
	testImageSize := uint64(1 << 23) // format requires more than 4194304 bytes
	options := NewRbdImageOptions()
	assert.NoError(t,
		options.SetUint64(ImageOptionOrder, uint64(testImageOrder)))
	err = CreateImage(ioctx, name, testImageSize, options)
	assert.NoError(t, err)

	workingImage, err := OpenImage(ioctx, name, NoSnapshot)
	assert.NoError(t, err)

	var opts EncryptionFormatOptsLUKS1
	opts.Alg = ENCRYPTION_ALGORITHM_AES256
	opts.Passphrase = ([]byte)("test-password")
	err = workingImage.EncryptionFormat(ENCRYPTION_FORMAT_LUKS1, opts)
	assert.NoError(t, err)

	err = workingImage.Close()
	assert.NoError(t, err)
	err = workingImage.Remove()
	assert.NoError(t, err)

	ioctx.Destroy()
	conn.DeletePool(poolname)
	conn.Shutdown()
}

func TestEncryptionLoad(t *testing.T) {
	conn := radosConnect(t)

	poolname := GetUUID()
	err := conn.MakePool(poolname)
	assert.NoError(t, err)

	ioctx, err := conn.OpenIOContext(poolname)
	require.NoError(t, err)

	name := GetUUID()
	testImageSize := uint64(1 << 23) // format requires more than 4194304 bytes
	options := NewRbdImageOptions()
	assert.NoError(t,
		options.SetUint64(ImageOptionOrder, uint64(testImageOrder)))
	err = CreateImage(ioctx, name, testImageSize, options)
	assert.NoError(t, err)

	img, err := OpenImage(ioctx, name, NoSnapshot)
	assert.NoError(t, err)

	var opts EncryptionFormatOptsLUKS1
	opts.Alg = ENCRYPTION_ALGORITHM_AES256
	opts.Passphrase = ([]byte)("test-password")

	err = img.EncryptionFormat(ENCRYPTION_FORMAT_LUKS1, opts)
	assert.NoError(t, err)

	err = img.EncryptionLoad(ENCRYPTION_FORMAT_LUKS1, opts)
	assert.NoError(t, err)

	// write some encrypted data at the end of the image
	data_out := []byte("Hi rbd! Nice to talk through go-ceph :)")

	stats, err := img.Stat()
	require.NoError(t, err)
	offset := int64(stats.Size) - int64(len(data_out))

   n_out, err := img.WriteAt(data_out, offset)
   assert.Equal(t, len(data_out), n_out)
   assert.NoError(t, err)

	// read the encrypted data 
   data_in := make([]byte, len(data_out))
   n_in, err := img.ReadAt(data_in, offset)
   assert.Equal(t, n_in, len(data_in))
   assert.Equal(t, data_in, data_out)
   assert.NoError(t, err)

	err = img.Close()
	assert.NoError(t, err)
	err = img.Remove()
	assert.NoError(t, err)

	// Re-open the image and read the encrypted data without loading the encryption 
	img, err := OpenImage(ioctx, name, NoSnapshot)
	assert.NoError(t, err)

   n_in, err = img.ReadAt(data_in, offset)
   assert.Equal(t, n_in, len(data_in))
   assert.Equal(t, data_in, data_out)
   assert.NoError(t, err)

	err = img.Close()
	assert.NoError(t, err)
	err = img.Remove()
	assert.NoError(t, err)

	ioctx.Destroy()
	conn.DeletePool(poolname)
	conn.Shutdown()
}

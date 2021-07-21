// +build !octopus,!nautilus

package rbd

// #cgo LDFLAGS: -lrbd
// /* force XSI-complaint strerror_r() */
// #define _POSIX_C_SOURCE 200112L
// #undef _GNU_SOURCE
// #include <errno.h>
// #include <stdlib.h>
// #include <rados/librados.h>
// #include <rbd/librbd.h>
import "C"

import (
	"unsafe"
)

// EncryptionFormat encryption format type
type EncryptionFormat C.uint

// Possible values for EncryptionFormat:
// ENCRYPTION_FORMAT_LUKS1: LUKS v1
// ENCRYPTION_FORMAT_LUKS2: LUKS v2
const (
	ENCRYPTION_FORMAT_LUKS1 = EncryptionFormat(C.RBD_ENCRYPTION_FORMAT_LUKS1)
	ENCRYPTION_FORMAT_LUKS2 = EncryptionFormat(C.RBD_ENCRYPTION_FORMAT_LUKS2)
)

// EncryptionAlgorithm encryption algorithm
type EncryptionAlgorithm C.uint

// Possible values for EncryptionAlgorithm:
// ENCRYPTION_ALGORITHM_AES128: AES 128bits
// ENCRYPTION_ALGORITHM_AES256: AES 256bits
const (
	ENCRYPTION_ALGORITHM_AES128 = EncryptionAlgorithm(C.RBD_ENCRYPTION_ALGORITHM_AES128)
	ENCRYPTION_ALGORITHM_AES256 = EncryptionAlgorithm(C.RBD_ENCRYPTION_ALGORITHM_AES256)
)

// EncryptionFormatOptsLUKS1 and EncryptionFormatOptsLUKS2 are identical
// structures at the moment, just as they are in the librbd api.
// The purpose behind creating different identical structures, is to facilitate
// future modifications of one of the formats, while maintaining backwards
// compatibility with the other.

// EncryptionFormatOptsLUKS1 options required for LUKS v1
type EncryptionFormatOptsLUKS1 struct {
	Alg        EncryptionAlgorithm
	Passphrase []byte
}

// EncryptionFormatOptsLUKS2 options required for LUKS v2
type EncryptionFormatOptsLUKS2 struct {
	Alg        EncryptionAlgorithm
	Passphrase []byte
}

// EncryptionOptions interface is used to encapsulate the different encryption
// formats options and enable converting them from go to C structures.
type EncryptionOptions interface {
	cephEncryptionOptions() (C.rbd_encryption_options_t, C.size_t)
}

func (opts EncryptionFormatOptsLUKS1) cephEncryptionOptions() (C.rbd_encryption_options_t, C.size_t) {
	var cOptsSize C.size_t
	var cOptsPtr C.rbd_encryption_options_t
	var cOpts C.rbd_encryption_luks1_format_options_t
	cOpts.alg = C.rbd_encryption_algorithm_t(opts.Alg)
	cOpts.passphrase = (*C.char)(C.CBytes(opts.Passphrase))
	cOpts.passphrase_size = C.ulong(len(opts.Passphrase))
	cOptsSize = C.size_t(unsafe.Sizeof(cOpts))
	cOptsPtr = C.rbd_encryption_options_t(&cOpts)
	return cOptsPtr, cOptsSize
}

func (opts EncryptionFormatOptsLUKS2) cephEncryptionOptions() (C.rbd_encryption_options_t, C.size_t) {
	var cOptsSize C.size_t
	var cOptsPtr C.rbd_encryption_options_t
	var cOpts C.rbd_encryption_luks2_format_options_t
	cOpts.alg = C.rbd_encryption_algorithm_t(opts.Alg)
	cOpts.passphrase = (*C.char)(C.CBytes(opts.Passphrase))
	cOpts.passphrase_size = C.ulong(len(opts.Passphrase))
	cOptsSize = C.size_t(unsafe.Sizeof(cOpts))
	cOptsPtr = C.rbd_encryption_options_t(&cOpts)
	return cOptsPtr, cOptsSize
}

// EncryptionFormat creates an encryption format header
//
// Implements:
//  int rbd_encryption_format(rbd_image_t image,
//                            rbd_encryption_format_t format,
//                            rbd_encryption_options_t opts,
//                            size_t opts_size);
//
// To issue an IO against the image, you need to mount the image
// with libvirt/qemu using the LUKS format, or make a call to
// EncryptionLoad() after opening the image.
func (image *Image) EncryptionFormat(format EncryptionFormat, opts EncryptionOptions) error {
	if image.image == nil {
		return ErrImageNotOpen
	}

	cOptsPtr, cOptsSize := opts.cephEncryptionOptions()

	ret := C.rbd_encryption_format(
		image.image,
		C.rbd_encryption_format_t(format),
		cOptsPtr,
		cOptsSize)
	return getError(ret)
}

// EncryptionLoad enables IO on an open encrypted image
//
// Implements:
//  int rbd_encryption_load(rbd_image_t image,
//                          rbd_encryption_format_t format,
//                          rbd_encryption_options_t opts,
//                          size_t opts_size);
func (image *Image) EncryptionLoad(format EncryptionFormat, opts EncryptionOptions) error {
	if image.image == nil {
		return ErrImageNotOpen
	}

	cOptsPtr, cOptsSize := opts.cephEncryptionOptions()

	ret := C.rbd_encryption_load(
		image.image,
		C.rbd_encryption_format_t(format),
		cOptsPtr,
		cOptsSize)
	return getError(ret)
}

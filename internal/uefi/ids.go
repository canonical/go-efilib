// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package uefi

var (
	EFI_HASH_ALGORITHM_SHA1_GUID   = New_EFI_GUID(0x2ae9d80f, 0x3fb2, 0x4095, 0xb7b1, [...]uint8{0xe9, 0x31, 0x57, 0xb9, 0x46, 0xb6})
	EFI_HASH_ALGORITHM_SHA256_GUID = New_EFI_GUID(0x51aa59de, 0xfdf2, 0x4ea3, 0xbc63, [...]uint8{0x87, 0x5f, 0xb7, 0x84, 0x2e, 0xe9})
	EFI_HASH_ALGORITHM_SHA224_GUID = New_EFI_GUID(0x8df01a06, 0x9bd5, 0x4bf7, 0xb021, [...]uint8{0xdb, 0x4f, 0xd9, 0xcc, 0xf4, 0x5b})
	EFI_HASH_ALGORITHM_SHA384_GUID = New_EFI_GUID(0xefa96432, 0xde33, 0x4dd2, 0xaee6, [...]uint8{0x32, 0x8c, 0x33, 0xdf, 0x77, 0x7a})
	EFI_HASH_ALGORITHM_SHA512_GUID = New_EFI_GUID(0xcaa4381e, 0x750c, 0x4770, 0xb870, [...]uint8{0x7a, 0x23, 0xb4, 0xe4, 0x21, 0x30})

	EFI_CERT_TYPE_RSA2048_SHA256_GUID = New_EFI_GUID(0xa7717414, 0xc616, 0x4977, 0x9420, [...]uint8{0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf})
	EFI_CERT_TYPE_PKCS7_GUID          = New_EFI_GUID(0x4aafd29d, 0x68df, 0x49ee, 0x8aa9, [...]uint8{0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7})

	EFI_CERT_SHA1_GUID   = New_EFI_GUID(0x826ca512, 0xcf10, 0x4ac9, 0xb187, [...]uint8{0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd})
	EFI_CERT_SHA256_GUID = New_EFI_GUID(0xc1c41626, 0x504c, 0x4092, 0xaca9, [...]uint8{0x41, 0xf9, 0x36, 0x93, 0x43, 0x28})
	EFI_CERT_SHA224_GUID = New_EFI_GUID(0xb6e5233, 0xa65c, 0x44c9, 0x9407, [...]uint8{0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd})
	EFI_CERT_SHA384_GUID = New_EFI_GUID(0xff3e5307, 0x9fd0, 0x48c9, 0x85f1, [...]uint8{0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01})
	EFI_CERT_SHA512_GUID = New_EFI_GUID(0x093e0fae, 0xa6c4, 0x4f50, 0x9f1b, [...]uint8{0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a})

	EFI_CERT_RSA2048_GUID        = New_EFI_GUID(0x3c5766e8, 0x269c, 0x4e34, 0xaa14, [...]uint8{0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6})
	EFI_CERT_RSA2048_SHA1_GUID   = New_EFI_GUID(0x67f8444f, 0x8743, 0x48f1, 0xa328, [...]uint8{0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80})
	EFI_CERT_RSA2048_SHA256_GUID = New_EFI_GUID(0xe2b36190, 0x879b, 0x4a3d, 0xad8d, [...]uint8{0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84})

	EFI_CERT_X509_GUID        = New_EFI_GUID(0xa5c059a1, 0x94e4, 0x4aa7, 0x87b5, [...]uint8{0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72})
	EFI_CERT_X509_SHA256_GUID = New_EFI_GUID(0x3bd2a492, 0x96c0, 0x4079, 0xb420, [...]uint8{0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed})
	EFI_CERT_X509_SHA384_GUID = New_EFI_GUID(0x7076876e, 0x80c2, 0x4ee6, 0xaad2, [...]uint8{0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b})
	EFI_CERT_X509_SHA512_GUID = New_EFI_GUID(0x446dbf63, 0x2502, 0x4cda, 0xbcfa, [...]uint8{0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d})

	EFI_GLOBAL_VARIABLE              = New_EFI_GUID(0x8be4df61, 0x93ca, 0x11d2, 0xaa0d, [...]uint8{0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})
	EFI_IMAGE_SECURITY_DATABASE_GUID = New_EFI_GUID(0xd719b2cb, 0x3d3a, 0x4596, 0xa3bc, [...]uint8{0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f})

	EFI_PC_ANSI_GUID                        = New_EFI_GUID(0xe0c14753, 0xf9be, 0x11d2, 0x9a0c, [...]uint8{0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d})
	EFI_VT_100_GUID                         = New_EFI_GUID(0xdfa66065, 0xb419, 0x11d3, 0x9a2d, [...]uint8{0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d})
	EFI_VT_100_PLUS_GUID                    = New_EFI_GUID(0x7baec70b, 0x57e0, 0x4c76, 0x8e87, [...]uint8{0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43})
	EFI_VT_UTF8_GUID                        = New_EFI_GUID(0xad15a0d6, 0x8bec, 0x4acf, 0xa073, [...]uint8{0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88})
	DEVICE_PATH_MESSAGING_UART_FLOW_CONTROL = New_EFI_GUID(0x37499a9d, 0x542f, 0x4c89, 0xa026, [...]uint8{0x35, 0xda, 0x14, 0x20, 0x94, 0xe4})
	EFI_SAS_DEVICE_PATH_GUID                = New_EFI_GUID(0xd487ddb4, 0x008b, 0x11d9, 0xafdc, [...]uint8{0x00, 0x10, 0x83, 0xff, 0xca, 0x4d})

	EFI_DEBUGPORT_PROTOCOL_GUID = New_EFI_GUID(0xeba4e8d2, 0x3858, 0x41ec, 0xa281, [...]uint8{0x26, 0x47, 0xba, 0x96, 0x60, 0xd0})
)

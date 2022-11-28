// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package pkcs7

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttribtes  []attribute `asn1:"optional,omitempty,tag:1"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}

func (r rawCertificates) Parse() ([]*x509.Certificate, error) {
	if len(r.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(r.Raw, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
}

type signedData struct {
	Version          int                        `asn1:"default:1"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     rawCertificates        `asn1:"optional,tag:0"`
	CRLs             []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo           `asn1:"set"`
}

type PKCS7 struct {
	Certificates []*x509.Certificate
	contentInfo  contentInfo
	signers      []issuerAndSerial
}

func UnmarshalPKCS7(data []byte) (*PKCS7, error) {
	n, data2, err := fixupBER(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	var sd signedData
	rest, err := asn1.Unmarshal(data2, &sd)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.StructuralError{Msg: "trailing data"}
	}

	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	var signers []issuerAndSerial
	for _, s := range sd.SignerInfos {
		signers = append(signers, s.IssuerAndSerialNumber)
	}

	return &PKCS7{
		Certificates: certs,
		contentInfo:  sd.ContentInfo,
		signers:      signers}, nil
}

func UnmarshalAuthenticode(data []byte) (*PKCS7, error) {
	n, data2, err := fixupBER(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	var info contentInfo
	rest, err := asn1.Unmarshal(data2, &info)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.StructuralError{Msg: "trailing data"}
	}

	if !info.ContentType.Equal(oidSignedData) {
		return nil, asn1.StructuralError{Msg: "not signed data"}
	}

	return UnmarshalPKCS7(info.Content.Bytes)
}

func (p *PKCS7) getCertFrom(ias *issuerAndSerial) *x509.Certificate {
	for _, c := range p.Certificates {
		if c.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, ias.IssuerName.FullBytes) {
			return c
		}
	}
	return nil
}

func (p *PKCS7) GetSigners() []*x509.Certificate {
	var certs []*x509.Certificate

	for _, s := range p.signers {
		c := p.getCertFrom(&s)
		if c == nil {
			return nil
		}
		certs = append(certs, c)
	}

	return certs
}

func (p *PKCS7) ContentType() asn1.ObjectIdentifier {
	return p.contentInfo.ContentType
}

func (p *PKCS7) Content() []byte {
	return p.contentInfo.Content.Bytes
}

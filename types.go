package efi

type PhysicalAddress uint64

// TableHeader corresponds to the EFI_TABLE_HEADER type.
type TableHeader struct {
	Signature  uint64
	Revision   uint32
	HeaderSize uint32
	CRC        uint32
	Reserved   uint32
}

// LBA corresponds to the EFI_LBA type.
type LBA uint64

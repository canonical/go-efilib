package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"unicode/utf16"

	"golang.org/x/xerrors"
)

// DevicePathType is the type of a device path node.
type DevicePathType uint8

func (t DevicePathType) String() string {
	switch t {
	case HardwareDevicePath:
		return "HardwarePath"
	case ACPIDevicePath:
		return "AcpiPath"
	case MessagingDevicePath:
		return "Msg"
	case MediaDevicePath:
		return "MediaPath"
	case BBSDevicePath:
		return "BbsPath"
	default:
		return fmt.Sprintf("Path[%02x]", uint8(t))
	}
}

const (
	HardwareDevicePath  DevicePathType = 0x01
	ACPIDevicePath      DevicePathType = 0x02
	MessagingDevicePath DevicePathType = 0x03
	MediaDevicePath     DevicePathType = 0x04
	BBSDevicePath       DevicePathType = 0x05
	endDevicePathType   DevicePathType = 0x7f
)

// DevicePathSubType is the sub-type of a device path node.
type DevicePathSubType uint8

const (
	hardwarePCIDevicePath DevicePathSubType = 0x01

	acpiNormalDevicePath DevicePathSubType = 0x01

	messagingSCSIDevicePath              DevicePathSubType = 0x02
	messagingUSBDevicePath               DevicePathSubType = 0x05
	messagingUSBClassDevicePath          DevicePathSubType = 0x0f
	messagingUSBWWIDDevicePath           DevicePathSubType = 0x10
	messagingDeviceLogicalUnitDevicePath DevicePathSubType = 0x11
	messagingSATADevicePath              DevicePathSubType = 0x12
	messagingNVMENamespaceDevicePath     DevicePathSubType = 0x17

	mediaHardDriveDevicePath      DevicePathSubType = 0x01
	mediaCDROMDevicePath          DevicePathSubType = 0x02
	mediaFilePathDevicePath       DevicePathSubType = 0x04
	mediaFvFileDevicePath         DevicePathSubType = 0x06
	mediaFvDevicePath             DevicePathSubType = 0x07
	mediaRelOffsetRangeDevicePath DevicePathSubType = 0x08
)

type devicePathNodeData interface {
	baseName() string
}

// DevicePathNode represents a single node in a device path.
type DevicePathNode struct {
	Parent *DevicePathNode // The parent node

	// Data provides additional information about this node. The concrete type is dependent on the type of this device path node,
	// and will be a pointer to one of the DevicePathData types.
	Data interface{}
}

// BaseName returns the string representation of this node.
func (n *DevicePathNode) BaseName() string {
	return n.Data.(devicePathNodeData).baseName()
}

// String returns the string representation of the full path of this node.
func (n *DevicePathNode) String() string {
	var nodes []*DevicePathNode
	for n != nil {
		nodes = append(nodes, n)
		n = n.Parent
	}

	var builder bytes.Buffer
	for i := len(nodes) - 1; i >= 0; i-- {
		fmt.Fprintf(&builder, "\\%s", nodes[i].BaseName())
	}
	return builder.String()
}

// RawDevicePathData provides information for device path nodes with an unhandled type.
type RawDevicePathData struct {
	Type    DevicePathType
	SubType DevicePathSubType
	Data    []byte
}

func (d *RawDevicePathData) baseName() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "%s(%d", d.Type, d.SubType)
	if len(d.Data) > 0 {
		fmt.Fprintf(&builder, ", 0x")
		for _, b := range d.Data {
			fmt.Fprintf(&builder, "%02x", b)
		}
	}
	fmt.Fprintf(&builder, ")")
	return builder.String()
}

// PCIDevicePathData provides information for PCI device path nodes.
type PCIDevicePathData struct {
	Function uint8
	Device   uint8
}

func (d *PCIDevicePathData) baseName() string {
	return fmt.Sprintf("Pci(0x%x,0x%x)", d.Device, d.Function)
}

// ACPIDevicePathData provides information for ACPI device path nodes.
type ACPIDevicePathData struct {
	HID uint32
	UID uint32
}

func (d *ACPIDevicePathData) baseName() string {
	if d.HID&0xffff == 0x41d0 {
		switch d.HID >> 16 {
		case 0x0a03:
			return fmt.Sprintf("PciRoot(0x%x)", d.UID)
		case 0x0a08:
			return fmt.Sprintf("PcieRoot(0x%x)", d.UID)
		case 0x0604:
			return fmt.Sprintf("Floppy(0x%x)", d.UID)
		default:
			return fmt.Sprintf("Acpi(PNP%04x,0x%x)", d.HID>>16, d.UID)
		}
	}
	return fmt.Sprintf("Acpi(0x%08x,0x%x)", d.HID, d.UID)
}

// SCSIDevicePathData provides information for SCSI device path nodes.
type SCSIDevicePathData struct {
	PUN uint16
	LUN uint16
}

func (d *SCSIDevicePathData) baseName() string {
	return fmt.Sprintf("Scsi(0x%x,0x%x)", d.PUN, d.LUN)
}

// USBDevicePathData provides information for USB device path nodes.
type USBDevicePathData struct {
	ParentPortNumber uint8
	InterfaceNumber  uint8
}

func (d *USBDevicePathData) baseName() string {
	return fmt.Sprintf("USB(0x%x,0x%x)", d.ParentPortNumber, d.InterfaceNumber)
}

type USBClass uint8

const (
	USBClassMassStorage USBClass = 0x08
	USBClassHub         USBClass = 0x09
)

// USBClassDevicePathData provides information for USB class device path nodes.
type USBClassDevicePathData struct {
	VendorId       uint16
	ProductId      uint16
	DeviceClass    USBClass
	DeviceSubClass uint8
	DeviceProtocol uint8
}

func (d *USBClassDevicePathData) baseName() string {
	var builder bytes.Buffer
	switch d.DeviceClass {
	case USBClassMassStorage:
		fmt.Fprintf(&builder, "UsbMassStorage")
	case USBClassHub:
		fmt.Fprintf(&builder, "UsbHub")
	default:
		return fmt.Sprintf("UsbClass(0x%x,0x%x,0x%x,0x%x,0x%x)", d.VendorId, d.ProductId, d.DeviceClass, d.DeviceSubClass, d.DeviceProtocol)
	}

	fmt.Fprintf(&builder, "(0x%x,0x%x,0x%x,0x%x)", d.VendorId, d.ProductId, d.DeviceSubClass, d.DeviceProtocol)
	return builder.String()
}

// USBWWIDDevicePathData provides information for USB WWID device path nodes.
type USBWWIDDevicePathData struct {
	InterfaceNumber uint16
	VendorId        uint16
	ProductId       uint16
	SerialNumber    string
}

func (d *USBWWIDDevicePathData) baseName() string {
	return fmt.Sprintf("UsbWwid(0x%x,0x%x,0x%x,\"%s\"", d.VendorId, d.ProductId, d.InterfaceNumber, d.SerialNumber)
}

type DeviceLogicalUnitDevicePathData struct {
	LUN uint8
}

func (d *DeviceLogicalUnitDevicePathData) baseName() string {
	return fmt.Sprintf("Unit(0x%x)", d.LUN)
}

// SATADevicePathData provides information for SATA device path nodes.
type SATADevicePathData struct {
	HBAPortNumber            uint16
	PortMultiplierPortNumber uint16
	LUN                      uint16
}

func (d *SATADevicePathData) baseName() string {
	return fmt.Sprintf("Sata(0x%x,0x%x,0x%x)", d.HBAPortNumber, d.PortMultiplierPortNumber, d.LUN)
}

// NVMENamespaceDevicePathData provides information for NVME namespace device path nodes.
type NVMENamespaceDevicePathData struct {
	NamespaceID   uint32
	NamespaceUUID uint64
}

func (d *NVMENamespaceDevicePathData) baseName() string {
	var uuid [8]uint8
	binary.BigEndian.PutUint64(uuid[:], d.NamespaceUUID)
	return fmt.Sprintf("NVMe(0x%x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x)", d.NamespaceID,
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7])
}

type MBRType uint8

const (
	LegacyMBR MBRType = 1
	GPT               = 2
)

// HardDriveDevicePathData provides information for hard drive device path nodes.
type HardDriveDevicePathData struct {
	PartitionNumber uint32
	PartitionStart  uint64
	PartitionSize   uint64
	Signature       interface{}
	MBRType         MBRType
}

func (d *HardDriveDevicePathData) baseName() string {
	var builder bytes.Buffer
	switch sig := d.Signature.(type) {
	case nil:
		fmt.Fprintf(&builder, "HD(%d,0,0,", d.PartitionNumber)
	case uint32:
		fmt.Fprintf(&builder, "HD(%d,MBR,0x%08x,", d.PartitionNumber, sig)
	case GUID:
		fmt.Fprintf(&builder, "HD(%d,GPT,%s,", d.PartitionNumber, sig)
	default:
		panic("invalid signature type")
	}

	fmt.Fprintf(&builder, "0x%016x,0x%016x)", d.PartitionStart, d.PartitionSize)
	return builder.String()
}

// CDROMDevicePathData provides information for CDROM device path nodes.
type CDROMDevicePathData struct {
	BootEntry      uint32
	PartitionStart uint64
	PartitionSize  uint64
}

func (d *CDROMDevicePathData) baseName() string {
	return fmt.Sprintf("CDROM(0x%x,0x%x,0x%x)", d.BootEntry, d.PartitionStart, d.PartitionSize)
}

// FilePathDevicePathData provides information for file path device path nodes.
type FilePathDevicePathData struct {
	PathName string
}

func (d *FilePathDevicePathData) baseName() string {
	return d.PathName
}

// MediaFvFileDevicePathData provides information for firmware volume file device path nodes.
type MediaFvFileDevicePathData struct {
	FvFileName GUID
}

func (d *MediaFvFileDevicePathData) baseName() string {
	return fmt.Sprintf("FvFile(%s)", d.FvFileName)
}

// MediaFvDevicePathData provides information for firmware volume device path nodes.
type MediaFvDevicePathData struct {
	FvName GUID
}

func (d *MediaFvDevicePathData) baseName() string {
	return fmt.Sprintf("Fv(%s)", d.FvName)
}

type MediaRelOffsetRangeDevicePathData struct {
	Reserved       uint32
	StartingOffset uint64
	EndingOffset   uint64
}

func (d *MediaRelOffsetRangeDevicePathData) baseName() string {
	return fmt.Sprintf("Offset(0x%x,0x%x)", d.StartingOffset, d.EndingOffset)
}

func decodeDevicePathNodeData(r io.Reader) (interface{}, error) {
	var h struct {
		Type    DevicePathType
		SubType DevicePathSubType
		Length  uint16
	}
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return nil, xerrors.Errorf("cannot read header: %w", err)
	}

	if h.Length < 4 {
		return nil, errors.New("invalid length")
	}

	d := make([]byte, int(h.Length-4))
	if _, err := io.ReadFull(r, d); err != nil {
		return nil, xerrors.Errorf("cannot read data: %w", err)
	}
	dr := bytes.NewReader(d)

	switch h.Type {
	case HardwareDevicePath:
		switch h.SubType {
		case hardwarePCIDevicePath:
			var n PCIDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		}
	case ACPIDevicePath:
		switch h.SubType {
		case acpiNormalDevicePath:
			var n ACPIDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		}
	case MessagingDevicePath:
		switch h.SubType {
		case messagingSCSIDevicePath:
			var n SCSIDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		case messagingUSBDevicePath:
			var n USBDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		case messagingUSBClassDevicePath:
			var n USBClassDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		case messagingUSBWWIDDevicePath:
			var s struct {
				InterfaceNumber uint16
				VendorId        uint16
				ProductId       uint16
			}
			if err := binary.Read(dr, binary.LittleEndian, &s); err != nil {
				return nil, err
			}
			serialBytes, err := ioutil.ReadAll(dr)
			if err != nil {
				return nil, err
			}
			serialU16 := make([]uint16, len(serialBytes)/2)
			if err := binary.Read(bytes.NewReader(serialBytes), binary.LittleEndian, &serialU16); err != nil {
				return nil, err
			}
			var serial bytes.Buffer
			for _, c := range utf16.Decode(serialU16) {
				serial.WriteRune(c)
			}
			return &USBWWIDDevicePathData{
				InterfaceNumber: s.InterfaceNumber,
				VendorId:        s.VendorId,
				ProductId:       s.ProductId,
				SerialNumber:    serial.String()}, nil
		case messagingDeviceLogicalUnitDevicePath:
			var n DeviceLogicalUnitDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		case messagingSATADevicePath:
			var n SATADevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		case messagingNVMENamespaceDevicePath:
			var n NVMENamespaceDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		}
	case MediaDevicePath:
		switch h.SubType {
		case mediaHardDriveDevicePath:
			var s struct {
				PartitionNumber uint32
				PartitionStart  uint64
				PartitionSize   uint64
				Signature       [16]byte
				MBRType         MBRType
				SignatureType   uint8
			}
			if err := binary.Read(dr, binary.LittleEndian, &s); err != nil {
				return nil, err
			}
			var signature interface{}
			switch s.SignatureType {
			case 0:
				signature = nil
			case 1:
				signature = binary.LittleEndian.Uint32(s.Signature[:])
			case 2:
				var g GUID
				copy(g[:], s.Signature[:])
				signature = g
			default:
				return nil, errors.New("invalid signature type")
			}
			return &HardDriveDevicePathData{
				PartitionNumber: s.PartitionNumber,
				PartitionStart:  s.PartitionStart,
				PartitionSize:   s.PartitionSize,
				Signature:       signature,
				MBRType:         s.MBRType}, nil
		case mediaCDROMDevicePath:
			var n CDROMDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		case mediaFilePathDevicePath:
			u16 := make([]uint16, dr.Len()/2)
			if err := binary.Read(dr, binary.LittleEndian, &u16); err != nil {
				return nil, err
			}
			var path bytes.Buffer
			for _, c := range utf16.Decode(u16) {
				path.WriteRune(c)
			}
			return &FilePathDevicePathData{PathName: strings.TrimRight(path.String(), "\x00")}, nil
		case mediaFvFileDevicePath:
			name, err := ReadGUID(dr)
			if err != nil {
				return nil, err
			}
			return &MediaFvFileDevicePathData{FvFileName: name}, nil
		case mediaFvDevicePath:
			name, err := ReadGUID(dr)
			if err != nil {
				return nil, err
			}
			return &MediaFvDevicePathData{FvName: name}, nil
		case mediaRelOffsetRangeDevicePath:
			var n MediaRelOffsetRangeDevicePathData
			if err := binary.Read(dr, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &n, nil
		}
	case endDevicePathType:
		return nil, nil
	}

	return &RawDevicePathData{Type: h.Type, SubType: h.SubType, Data: d}, nil
}

// DecodeDevicePath decodes a device path from the supplied io.Reader.
func DecodeDevicePath(r io.Reader) (*DevicePathNode, error) {
	var nodeData []interface{}
	for i := 0; ; i++ {
		d, err := decodeDevicePathNodeData(r)
		if err != nil {
			return nil, xerrors.Errorf("cannot decode node %d: %w", i, err)
		}
		if d == nil {
			break
		}
		nodeData = append(nodeData, d)
	}

	var nodes []*DevicePathNode
	for _, d := range nodeData {
		nodes = append(nodes, &DevicePathNode{Data: d})
	}
	for i := len(nodes) - 1; i > 0; i-- {
		nodes[i].Parent = nodes[i-1]
	}

	return nodes[len(nodes)-1], nil
}

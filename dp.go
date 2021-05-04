// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package efi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/canonical/go-efilib/internal/ioerr"
	"github.com/canonical/go-efilib/internal/uefi"

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
	HardwareDevicePath  DevicePathType = uefi.HARDWARE_DEVICE_PATH
	ACPIDevicePath      DevicePathType = uefi.ACPI_DEVICE_PATH
	MessagingDevicePath DevicePathType = uefi.MESSAGING_DEVICE_PATH
	MediaDevicePath     DevicePathType = uefi.MEDIA_DEVICE_PATH
	BBSDevicePath       DevicePathType = uefi.BBS_DEVICE_PATH
)

// DevicePathSubType is the sub-type of a device path node.
type DevicePathSubType uint8

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
	StartingOffset uint64
	EndingOffset   uint64
}

func (d *MediaRelOffsetRangeDevicePathData) baseName() string {
	return fmt.Sprintf("Offset(0x%x,0x%x)", d.StartingOffset, d.EndingOffset)
}

func decodeDevicePathNodeData(r io.Reader) (interface{}, error) {
	buf := new(bytes.Buffer)
	r2 := io.TeeReader(r, buf)

	var h uefi.EFI_DEVICE_PATH_PROTOCOL
	if err := binary.Read(r2, binary.LittleEndian, &h); err != nil {
		return nil, ioerr.PassEOF("cannot read header", err)
	}

	if h.Length < 4 {
		return nil, errors.New("invalid length")
	}

	if _, err := io.CopyN(buf, r, int64(h.Length-4)); err != nil {
		return nil, ioerr.EOFUnexpected("cannot read data", err)
	}

	switch h.Type {
	case uefi.HARDWARE_DEVICE_PATH:
		switch h.SubType {
		case uefi.HW_PCI_DP:
			var n uefi.PCI_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &PCIDevicePathData{Function: n.Function, Device: n.Device}, nil
		}
	case uefi.ACPI_DEVICE_PATH:
		switch h.SubType {
		case uefi.ACPI_DP:
			var n uefi.ACPI_HID_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &ACPIDevicePathData{HID: n.HID, UID: n.UID}, nil
		}
	case uefi.MESSAGING_DEVICE_PATH:
		switch h.SubType {
		case uefi.MSG_SCSI_DP:
			var n uefi.SCSI_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &SCSIDevicePathData{PUN: n.Pun, LUN: n.Lun}, nil
		case uefi.MSG_USB_DP:
			var n uefi.USB_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &USBDevicePathData{ParentPortNumber: n.ParentPortNumber, InterfaceNumber: n.InterfaceNumber}, nil
		case uefi.MSG_USB_CLASS_DP:
			var n uefi.USB_CLASS_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &USBClassDevicePathData{
				VendorId:       n.VendorId,
				ProductId:      n.ProductId,
				DeviceClass:    USBClass(n.DeviceClass),
				DeviceSubClass: n.DeviceSubClass,
				DeviceProtocol: n.DeviceProtocol}, nil
		case uefi.MSG_USB_WWID_DP:
			n, err := uefi.Read_USB_WWID_DEVICE_PATH(buf)
			if err != nil {
				return nil, err
			}
			var serial bytes.Buffer
			for _, c := range utf16.Decode(n.SerialNumber) {
				serial.WriteRune(c)
			}
			return &USBWWIDDevicePathData{
				InterfaceNumber: n.InterfaceNumber,
				VendorId:        n.VendorId,
				ProductId:       n.ProductId,
				SerialNumber:    serial.String()}, nil
		case uefi.MSG_DEVICE_LOGICAL_UNIT_DP:
			var n uefi.DEVICE_LOGICAL_UNIT_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &DeviceLogicalUnitDevicePathData{LUN: n.Lun}, nil
		case uefi.MSG_SATA_DP:
			var n uefi.SATA_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &SATADevicePathData{
				HBAPortNumber:            n.HBAPortNumber,
				PortMultiplierPortNumber: n.PortMultiplierPortNumber,
				LUN:                      n.Lun}, nil
		case uefi.MSG_NVME_NAMESPACE_DP:
			var n uefi.NVME_NAMESPACE_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &NVMENamespaceDevicePathData{
				NamespaceID:   n.NamespaceId,
				NamespaceUUID: n.NamespaceUuid}, nil
		}
	case uefi.MEDIA_DEVICE_PATH:
		switch h.SubType {
		case uefi.MEDIA_HARDDRIVE_DP:
			var n uefi.HARDDRIVE_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}

			var signature interface{}
			switch n.SignatureType {
			case uefi.NO_DISK_SIGNATURE:
				signature = nil
			case uefi.SIGNATURE_TYPE_MBR:
				signature = binary.LittleEndian.Uint32(n.Signature[:])
			case uefi.SIGNATURE_TYPE_GUID:
				signature = GUID(n.Signature)
			default:
				return nil, errors.New("invalid signature type")
			}
			return &HardDriveDevicePathData{
				PartitionNumber: n.PartitionNumber,
				PartitionStart:  n.PartitionStart,
				PartitionSize:   n.PartitionSize,
				Signature:       signature,
				MBRType:         MBRType(n.MBRType)}, nil
		case uefi.MEDIA_CDROM_DP:
			var n uefi.CDROM_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &CDROMDevicePathData{
				BootEntry:      n.BootEntry,
				PartitionStart: n.PartitionStart,
				PartitionSize:  n.PartitionSize}, nil
		case uefi.MEDIA_FILEPATH_DP:
			n, err := uefi.Read_FILEPATH_DEVICE_PATH(buf)
			if err != nil {
				return nil, err
			}
			var path bytes.Buffer
			for _, c := range utf16.Decode(n.PathName) {
				path.WriteRune(c)
			}
			return &FilePathDevicePathData{PathName: strings.TrimRight(path.String(), "\x00")}, nil
		case uefi.MEDIA_PIWG_FW_FILE_DP:
			var n uefi.MEDIA_FW_VOL_FILEPATH_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &MediaFvFileDevicePathData{FvFileName: GUID(n.FvFileName)}, nil
		case uefi.MEDIA_PIWG_FW_VOL_DP:
			var n uefi.MEDIA_FW_VOL_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &MediaFvDevicePathData{FvName: GUID(n.FvName)}, nil
		case uefi.MEDIA_RELATIVE_OFFSET_RANGE_DP:
			var n uefi.MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &MediaRelOffsetRangeDevicePathData{StartingOffset: n.StartingOffset, EndingOffset: n.EndingOffset}, nil
		}
	case uefi.END_DEVICE_PATH_TYPE:
		return nil, nil
	}

	return &RawDevicePathData{Type: DevicePathType(h.Type), SubType: DevicePathSubType(h.SubType), Data: buf.Bytes()[binary.Size(h):]}, nil
}

// ReadDevicePath decodes a device path from the supplied io.Reader.
func ReadDevicePath(r io.Reader) (*DevicePathNode, error) {
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

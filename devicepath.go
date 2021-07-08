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
	"math"

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

// DevicePathNode represents a single node in a device path.
type DevicePathNode interface {
	fmt.Stringer
	Write(w io.Writer) error
}

// DevicePath represents a complete device path with the first node
// representing the root.
type DevicePath []DevicePathNode

func (p DevicePath) String() string {
	s := new(bytes.Buffer)
	for _, node := range p {
		fmt.Fprintf(s, "\\%s", node)
	}
	return s.String()
}

// Write serializes the complete device path to w.
func (p DevicePath) Write(w io.Writer) error {
	for i, node := range p {
		if err := node.Write(w); err != nil {
			return xerrors.Errorf("cannot write node %d: %w", i, err)
		}
	}

	end := uefi.EFI_DEVICE_PATH_PROTOCOL{
		Type:    uefi.END_DEVICE_PATH_TYPE,
		SubType: uefi.END_ENTIRE_DEVICE_PATH_SUBTYPE,
		Length:  4}
	return binary.Write(w, binary.LittleEndian, &end)
}

// RawDevicePathNode corresponds to a device path nodes with an unhandled type.
type RawDevicePathNode struct {
	Type    DevicePathType
	SubType DevicePathSubType
	Data    []byte
}

func (d *RawDevicePathNode) String() string {
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

func (d *RawDevicePathNode) Write(w io.Writer) error {
	data := uefi.EFI_DEVICE_PATH_PROTOCOL{
		Type:    uint8(d.Type),
		SubType: uint8(d.SubType)}

	l := binary.Size(data) + len(d.Data)
	if l > math.MaxUint16 {
		return errors.New("data too large")
	}
	data.Length = uint16(l)

	if err := binary.Write(w, binary.LittleEndian, &data); err != nil {
		return err
	}
	_, err := w.Write(d.Data)
	return err
}

// PCIDevicePathNode corresponds to a PCI device path node.
type PCIDevicePathNode struct {
	Function uint8
	Device   uint8
}

func (d *PCIDevicePathNode) String() string {
	return fmt.Sprintf("Pci(0x%x,0x%x)", d.Device, d.Function)
}

func (d *PCIDevicePathNode) Write(w io.Writer) error {
	data := uefi.PCI_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.HARDWARE_DEVICE_PATH),
			SubType: uint8(uefi.HW_PCI_DP)},
		Function: d.Function,
		Device:   d.Device}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// ACPIDevicePathNode corresponds to an ACPI device path node.
type ACPIDevicePathNode struct {
	HID uint32
	UID uint32
}

func (d *ACPIDevicePathNode) String() string {
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

func (d *ACPIDevicePathNode) Write(w io.Writer) error {
	data := uefi.ACPI_HID_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.ACPI_DEVICE_PATH),
			SubType: uint8(uefi.ACPI_DP)},
		HID: d.HID,
		UID: d.UID}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// SCSIDevicePathNode corresponds to a SCSI device path node.
type SCSIDevicePathNode struct {
	PUN uint16
	LUN uint16
}

func (d *SCSIDevicePathNode) String() string {
	return fmt.Sprintf("Scsi(0x%x,0x%x)", d.PUN, d.LUN)
}

func (d *SCSIDevicePathNode) Write(w io.Writer) error {
	data := uefi.SCSI_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_SCSI_DP)},
		Pun: d.PUN,
		Lun: d.LUN}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// USBDevicePathNode corresponds to a USB device path node.
type USBDevicePathNode struct {
	ParentPortNumber uint8
	InterfaceNumber  uint8
}

func (d *USBDevicePathNode) String() string {
	return fmt.Sprintf("USB(0x%x,0x%x)", d.ParentPortNumber, d.InterfaceNumber)
}

func (d *USBDevicePathNode) Write(w io.Writer) error {
	data := uefi.USB_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_USB_DP)},
		ParentPortNumber: d.ParentPortNumber,
		InterfaceNumber:  d.InterfaceNumber}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

type USBClass uint8

const (
	USBClassMassStorage USBClass = 0x08
	USBClassHub         USBClass = 0x09
)

// USBClassDevicePathNode corresponds to a USB class device path node.
type USBClassDevicePathNode struct {
	VendorId       uint16
	ProductId      uint16
	DeviceClass    USBClass
	DeviceSubClass uint8
	DeviceProtocol uint8
}

func (d *USBClassDevicePathNode) String() string {
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

func (d *USBClassDevicePathNode) Write(w io.Writer) error {
	data := uefi.USB_CLASS_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_USB_CLASS_DP)},
		VendorId:       d.VendorId,
		ProductId:      d.ProductId,
		DeviceClass:    uint8(d.DeviceClass),
		DeviceSubClass: d.DeviceSubClass,
		DeviceProtocol: d.DeviceProtocol}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// USBWWIDDevicePathNode corresponds to a USB WWID device path node.
type USBWWIDDevicePathNode struct {
	InterfaceNumber uint16
	VendorId        uint16
	ProductId       uint16
	SerialNumber    string
}

func (d *USBWWIDDevicePathNode) String() string {
	return fmt.Sprintf("UsbWwid(0x%x,0x%x,0x%x,\"%s\"", d.VendorId, d.ProductId, d.InterfaceNumber, d.SerialNumber)
}

func (d *USBWWIDDevicePathNode) Write(w io.Writer) error {
	data := uefi.USB_WWID_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_USB_WWID_DP)},
		InterfaceNumber: d.InterfaceNumber,
		VendorId:        d.VendorId,
		ProductId:       d.ProductId,
		SerialNumber:    ConvertUTF8ToUTF16(d.SerialNumber)}

	data.Header.Length = uint16(binary.Size(data.Header) + binary.Size(data.InterfaceNumber) + binary.Size(data.VendorId) + binary.Size(data.ProductId) + binary.Size(data.SerialNumber))

	return binary.Write(w, binary.LittleEndian, &data)
}

type DeviceLogicalUnitDevicePathNode struct {
	LUN uint8
}

func (d *DeviceLogicalUnitDevicePathNode) String() string {
	return fmt.Sprintf("Unit(0x%x)", d.LUN)
}

func (d *DeviceLogicalUnitDevicePathNode) Write(w io.Writer) error {
	data := uefi.DEVICE_LOGICAL_UNIT_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_DEVICE_LOGICAL_UNIT_DP)},
		Lun: d.LUN}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// SATADevicePathNode corresponds to a SATA device path node.
type SATADevicePathNode struct {
	HBAPortNumber            uint16
	PortMultiplierPortNumber uint16
	LUN                      uint16
}

func (d *SATADevicePathNode) String() string {
	return fmt.Sprintf("Sata(0x%x,0x%x,0x%x)", d.HBAPortNumber, d.PortMultiplierPortNumber, d.LUN)
}

func (d *SATADevicePathNode) Write(w io.Writer) error {
	data := uefi.SATA_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_SATA_DP)},
		HBAPortNumber:            d.HBAPortNumber,
		PortMultiplierPortNumber: d.PortMultiplierPortNumber,
		Lun:                      d.LUN}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// NVMENamespaceDevicePathNode corresponds to a NVME namespace device path node.
type NVMENamespaceDevicePathNode struct {
	NamespaceID   uint32
	NamespaceUUID uint64
}

func (d *NVMENamespaceDevicePathNode) String() string {
	var uuid [8]uint8
	binary.BigEndian.PutUint64(uuid[:], d.NamespaceUUID)
	return fmt.Sprintf("NVMe(0x%x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x-0x%02x)", d.NamespaceID,
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7])
}

func (d *NVMENamespaceDevicePathNode) Write(w io.Writer) error {
	data := uefi.NVME_NAMESPACE_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MESSAGING_DEVICE_PATH),
			SubType: uint8(uefi.MSG_NVME_NAMESPACE_DP)},
		NamespaceId:   d.NamespaceID,
		NamespaceUuid: d.NamespaceUUID}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

type MBRType uint8

const (
	LegacyMBR MBRType = 1
	GPT               = 2
)

// HardDriveDevicePathNode corresponds to a hard drive device path node.
type HardDriveDevicePathNode struct {
	PartitionNumber uint32
	PartitionStart  uint64
	PartitionSize   uint64
	Signature       interface{}
	MBRType         MBRType
}

func (d *HardDriveDevicePathNode) String() string {
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

func (d *HardDriveDevicePathNode) Write(w io.Writer) error {
	data := uefi.HARDDRIVE_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MEDIA_DEVICE_PATH),
			SubType: uint8(uefi.MEDIA_HARDDRIVE_DP)},
		PartitionNumber: d.PartitionNumber,
		PartitionStart:  d.PartitionStart,
		PartitionSize:   d.PartitionSize,
		MBRType:         uint8(d.MBRType)}

	switch sig := d.Signature.(type) {
	case nil:
		data.SignatureType = uefi.NO_DISK_SIGNATURE
		_ = sig
	case uint32:
		data.SignatureType = uefi.SIGNATURE_TYPE_MBR
		binary.LittleEndian.PutUint32(data.Signature[:], sig)
	case GUID:
		data.SignatureType = uefi.SIGNATURE_TYPE_GUID
		copy(data.Signature[:], sig[:])
	default:
		return errors.New("unexpected signature type")
	}

	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// CDROMDevicePathNode corresponds to a CDROM device path node.
type CDROMDevicePathNode struct {
	BootEntry      uint32
	PartitionStart uint64
	PartitionSize  uint64
}

func (d *CDROMDevicePathNode) String() string {
	return fmt.Sprintf("CDROM(0x%x,0x%x,0x%x)", d.BootEntry, d.PartitionStart, d.PartitionSize)
}

func (d *CDROMDevicePathNode) Write(w io.Writer) error {
	data := uefi.CDROM_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MEDIA_DEVICE_PATH),
			SubType: uint8(uefi.MEDIA_CDROM_DP)},
		BootEntry:      d.BootEntry,
		PartitionStart: d.PartitionStart,
		PartitionSize:  d.PartitionSize}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// FilePathDevicePathNode corresponds to a file path device path node.
type FilePathDevicePathNode string

func (d FilePathDevicePathNode) String() string {
	return string(d)
}

func (d FilePathDevicePathNode) Write(w io.Writer) error {
	data := uefi.FILEPATH_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MEDIA_DEVICE_PATH),
			SubType: uint8(uefi.MEDIA_FILEPATH_DP)},
		PathName: ConvertUTF8ToUTF16(string(d) + "\x00")}
	data.Header.Length = uint16(binary.Size(data.Header) + binary.Size(data.PathName))

	return data.Write(w)
}

// MediaFvFileDevicePathNode corresponds to a firmware volume file device path node.
type MediaFvFileDevicePathNode GUID

func (d MediaFvFileDevicePathNode) String() string {
	return fmt.Sprintf("FvFile(%s)", GUID(d))
}

func (d MediaFvFileDevicePathNode) Write(w io.Writer) error {
	data := uefi.MEDIA_FW_VOL_FILEPATH_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MEDIA_DEVICE_PATH),
			SubType: uint8(uefi.MEDIA_PIWG_FW_FILE_DP)},
		FvFileName: uefi.EFI_GUID(d)}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

// MediaFvDevicePathNode corresponds to a firmware volume device path node.
type MediaFvDevicePathNode GUID

func (d MediaFvDevicePathNode) String() string {
	return fmt.Sprintf("Fv(%s)", GUID(d))
}

func (d MediaFvDevicePathNode) Write(w io.Writer) error {
	data := uefi.MEDIA_FW_VOL_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MEDIA_DEVICE_PATH),
			SubType: uint8(uefi.MEDIA_PIWG_FW_VOL_DP)},
		FvName: uefi.EFI_GUID(d)}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

type MediaRelOffsetRangeDevicePathNode struct {
	StartingOffset uint64
	EndingOffset   uint64
}

func (d *MediaRelOffsetRangeDevicePathNode) String() string {
	return fmt.Sprintf("Offset(0x%x,0x%x)", d.StartingOffset, d.EndingOffset)
}

func (d *MediaRelOffsetRangeDevicePathNode) Write(w io.Writer) error {
	data := uefi.MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH{
		Header: uefi.EFI_DEVICE_PATH_PROTOCOL{
			Type:    uint8(uefi.MEDIA_DEVICE_PATH),
			SubType: uint8(uefi.MEDIA_RELATIVE_OFFSET_RANGE_DP)},
		StartingOffset: d.StartingOffset,
		EndingOffset:   d.EndingOffset}
	data.Header.Length = uint16(binary.Size(data))

	return binary.Write(w, binary.LittleEndian, &data)
}

func decodeDevicePathNode(r io.Reader) (DevicePathNode, error) {
	buf := new(bytes.Buffer)
	r2 := io.TeeReader(r, buf)

	var h uefi.EFI_DEVICE_PATH_PROTOCOL
	if err := binary.Read(r2, binary.LittleEndian, &h); err != nil {
		return nil, ioerr.PassRawEOF("cannot read header: %w", err)
	}

	if h.Length < 4 {
		return nil, errors.New("invalid length")
	}

	if _, err := io.CopyN(buf, r, int64(h.Length-4)); err != nil {
		return nil, ioerr.EOFIsUnexpected("cannot read data: %w", err)
	}

	switch h.Type {
	case uefi.HARDWARE_DEVICE_PATH:
		switch h.SubType {
		case uefi.HW_PCI_DP:
			var n uefi.PCI_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &PCIDevicePathNode{Function: n.Function, Device: n.Device}, nil
		}
	case uefi.ACPI_DEVICE_PATH:
		switch h.SubType {
		case uefi.ACPI_DP:
			var n uefi.ACPI_HID_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &ACPIDevicePathNode{HID: n.HID, UID: n.UID}, nil
		}
	case uefi.MESSAGING_DEVICE_PATH:
		switch h.SubType {
		case uefi.MSG_SCSI_DP:
			var n uefi.SCSI_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &SCSIDevicePathNode{PUN: n.Pun, LUN: n.Lun}, nil
		case uefi.MSG_USB_DP:
			var n uefi.USB_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &USBDevicePathNode{ParentPortNumber: n.ParentPortNumber, InterfaceNumber: n.InterfaceNumber}, nil
		case uefi.MSG_USB_CLASS_DP:
			var n uefi.USB_CLASS_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &USBClassDevicePathNode{
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
			return &USBWWIDDevicePathNode{
				InterfaceNumber: n.InterfaceNumber,
				VendorId:        n.VendorId,
				ProductId:       n.ProductId,
				SerialNumber:    ConvertUTF16ToUTF8(n.SerialNumber)}, nil
		case uefi.MSG_DEVICE_LOGICAL_UNIT_DP:
			var n uefi.DEVICE_LOGICAL_UNIT_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &DeviceLogicalUnitDevicePathNode{LUN: n.Lun}, nil
		case uefi.MSG_SATA_DP:
			var n uefi.SATA_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &SATADevicePathNode{
				HBAPortNumber:            n.HBAPortNumber,
				PortMultiplierPortNumber: n.PortMultiplierPortNumber,
				LUN:                      n.Lun}, nil
		case uefi.MSG_NVME_NAMESPACE_DP:
			var n uefi.NVME_NAMESPACE_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &NVMENamespaceDevicePathNode{
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
			return &HardDriveDevicePathNode{
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
			return &CDROMDevicePathNode{
				BootEntry:      n.BootEntry,
				PartitionStart: n.PartitionStart,
				PartitionSize:  n.PartitionSize}, nil
		case uefi.MEDIA_FILEPATH_DP:
			n, err := uefi.Read_FILEPATH_DEVICE_PATH(buf)
			if err != nil {
				return nil, err
			}
			return FilePathDevicePathNode(ConvertUTF16ToUTF8(n.PathName)), nil
		case uefi.MEDIA_PIWG_FW_FILE_DP:
			var n uefi.MEDIA_FW_VOL_FILEPATH_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return MediaFvFileDevicePathNode(GUID(n.FvFileName)), nil
		case uefi.MEDIA_PIWG_FW_VOL_DP:
			var n uefi.MEDIA_FW_VOL_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return MediaFvDevicePathNode(GUID(n.FvName)), nil
		case uefi.MEDIA_RELATIVE_OFFSET_RANGE_DP:
			var n uefi.MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH
			if err := binary.Read(buf, binary.LittleEndian, &n); err != nil {
				return nil, err
			}
			return &MediaRelOffsetRangeDevicePathNode{StartingOffset: n.StartingOffset, EndingOffset: n.EndingOffset}, nil
		}
	case uefi.END_DEVICE_PATH_TYPE:
		return nil, nil
	}

	return &RawDevicePathNode{Type: DevicePathType(h.Type), SubType: DevicePathSubType(h.SubType), Data: buf.Bytes()[binary.Size(h):]}, nil
}

// ReadDevicePath decodes a device path from the supplied io.Reader.
func ReadDevicePath(r io.Reader) (out DevicePath, err error) {
	for i := 0; ; i++ {
		node, err := decodeDevicePathNode(r)
		switch {
		case err != nil && i == 0:
			return nil, ioerr.PassRawEOF("cannot decode node %d: %w", i, err)
		case err != nil:
			return nil, ioerr.EOFIsUnexpected("cannot decode node: %d: %w", i, err)
		}
		if node == nil {
			break
		}
		out = append(out, node)
	}
	return out, nil
}

#!/usr/bin/env bash
# Build a VMware OVA from the streamOptimized VMDK the post-processor already
# produced, so ESXi / vSphere can deploy it in one step ("Deploy OVF Template",
# ovftool, or `govc import.ova`) — no manual `govc import.vmdk` conversion.
#
# An OVA is just an (uncompressed) tar of: the .ovf descriptor (VM hardware:
# cpu/mem/disk/nic), then the .mf manifest (SHA256 of each member), then the
# streamOptimized .vmdk — in that order (the descriptor MUST be first). We hand-
# build the OVF (no ovftool / VMware license needed in CI). The disk stays
# streamOptimized, so the OVA is ~the same size as the standalone vmdk.
#
# Usage: make-ova.sh <version> <dist-dir>
set -euo pipefail

VER="${1:?version required}"
DIST="${2:?dist dir required}"
cd "$DIST"

BASE="soctalk-demo-${VER}"
VMDK="${BASE}.vmdk"
OVF="${BASE}.ovf"
MF="${BASE}.mf"
OVA="${BASE}.ova"

[[ -f "$VMDK" ]] || { echo "::error::$VMDK not found (OVA needs the streamOptimized vmdk)"; exit 1; }

VMDK_BYTES=$(stat -c%s "$VMDK")
CAP_GIB=60   # matches source.qemu disk_size = "60G"

echo "==> writing OVF descriptor ($VMDK = ${VMDK_BYTES} bytes)"
cat > "$OVF" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"
  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf"
  xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="${VMDK}" ovf:id="file1" ovf:size="${VMDK_BYTES}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="${CAP_GIB}" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="soctalk-demo-${VER}">
    <Info>SocTalk demo appliance</Info>
    <Name>soctalk-demo-${VER}</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="ubuntu64Guest">
      <Info>The kind of installed guest operating system</Info>
      <Description>Ubuntu Linux (64-bit)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>soctalk-demo-${VER}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>4 virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>4</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>8192MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>8192</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>scsiController0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>disk0</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VmxNet3 ethernet adapter</rasd:Description>
        <rasd:ElementName>ethernet0</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
EOF

echo "==> writing manifest ($MF)"
{
  printf 'SHA256(%s)= %s\n' "$OVF" "$(sha256sum "$OVF" | awk '{print $1}')"
  printf 'SHA256(%s)= %s\n' "$VMDK" "$(sha256sum "$VMDK" | awk '{print $1}')"
} > "$MF"

echo "==> packing $OVA (ovf, mf, vmdk — descriptor first)"
# OVA = uncompressed tar; the disk inside is already streamOptimized-compressed.
tar -cf "$OVA" "$OVF" "$MF" "$VMDK"

# Keep only the .ova (drop the loose descriptor/manifest so later steps that
# glob dist/ don't pick them up; the vmdk stays for its own .vmdk.xz artifact).
rm -f "$OVF" "$MF"

echo "==> built $(ls -lh "$OVA" | awk '{print $NF, $5}')"

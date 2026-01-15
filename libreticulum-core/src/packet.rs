//! Packet structure and serialization
//!
//! Packet format:
//! [Flags (1)] [Hops (1)] [Header (19-35)] [Context (1)] [Payload (variable)]
//!
//! The header size depends on header type:
//! - Header Type 1: destination_hash only (16 bytes)
//! - Header Type 2: transport_id + destination_hash (32 bytes)

use crate::constants::{HEADER_MAXSIZE, HEADER_MINSIZE, MDU, MTU, TRUNCATED_HASHBYTES};
use crate::destination::DestinationType;

/// Packet type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Regular data packet
    Data = 0x00,
    /// Destination presence announcement
    Announce = 0x01,
    /// Link establishment request
    LinkRequest = 0x02,
    /// Proof/receipt
    Proof = 0x03,
}

impl TryFrom<u8> for PacketType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0x03 {
            0x00 => Ok(PacketType::Data),
            0x01 => Ok(PacketType::Announce),
            0x02 => Ok(PacketType::LinkRequest),
            0x03 => Ok(PacketType::Proof),
            _ => Err(()),
        }
    }
}

/// Transport type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportType {
    /// Broadcast to all reachable interfaces
    Broadcast = 0x00,
    /// Routed via transport layer
    Transport = 0x01,
}

/// Header type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderType {
    /// Header Type 1: destination_hash only
    Type1 = 0x00,
    /// Header Type 2: transport_id + destination_hash
    Type2 = 0x01,
}

/// Packet context (stored in context byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketContext {
    None = 0x00,
    Resource = 0x01,
    ResourceAdv = 0x02,
    ResourceReq = 0x03,
    ResourceHmu = 0x04,
    ResourcePrf = 0x05,
    ResourceIcl = 0x06,
    ResourceRcl = 0x07,
    CacheRequest = 0x08,
    Request = 0x09,
    Response = 0x0A,
    PathResponse = 0x0B,
    Command = 0x0C,
    CommandStatus = 0x0D,
    Channel = 0x0E,
    Keepalive = 0xFA,
    LinkIdentify = 0xFB,
    LinkClose = 0xFC,
    LinkProof = 0xFD,
    Lrrtt = 0xFE,
    Lrproof = 0xFF,
}

impl TryFrom<u8> for PacketContext {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(PacketContext::None),
            0x01 => Ok(PacketContext::Resource),
            0x02 => Ok(PacketContext::ResourceAdv),
            0x03 => Ok(PacketContext::ResourceReq),
            0x04 => Ok(PacketContext::ResourceHmu),
            0x05 => Ok(PacketContext::ResourcePrf),
            0x06 => Ok(PacketContext::ResourceIcl),
            0x07 => Ok(PacketContext::ResourceRcl),
            0x08 => Ok(PacketContext::CacheRequest),
            0x09 => Ok(PacketContext::Request),
            0x0A => Ok(PacketContext::Response),
            0x0B => Ok(PacketContext::PathResponse),
            0x0C => Ok(PacketContext::Command),
            0x0D => Ok(PacketContext::CommandStatus),
            0x0E => Ok(PacketContext::Channel),
            0xFA => Ok(PacketContext::Keepalive),
            0xFB => Ok(PacketContext::LinkIdentify),
            0xFC => Ok(PacketContext::LinkClose),
            0xFD => Ok(PacketContext::LinkProof),
            0xFE => Ok(PacketContext::Lrrtt),
            0xFF => Ok(PacketContext::Lrproof),
            _ => Err(()),
        }
    }
}

/// Packet flags byte layout:
/// Bit 7: Header Type (0=H1, 1=H2)
/// Bit 6: Context Flag (0=unset, 1=set)
/// Bit 5: Transport Type (0=broadcast, 1=transport)
/// Bits 4-3: Destination Type
/// Bits 1-0: Packet Type
#[derive(Debug, Clone, Copy)]
pub struct PacketFlags {
    pub header_type: HeaderType,
    pub context_flag: bool,
    pub transport_type: TransportType,
    pub dest_type: DestinationType,
    pub packet_type: PacketType,
}

impl PacketFlags {
    /// Encode flags to a byte
    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        flags |= (self.header_type as u8) << 7;
        flags |= (self.context_flag as u8) << 6;
        flags |= (self.transport_type as u8) << 5;
        flags |= (self.dest_type as u8) << 3;
        flags |= self.packet_type as u8;
        flags
    }

    /// Decode flags from a byte
    pub fn from_byte(byte: u8) -> Result<Self, PacketError> {
        let header_type = if byte & 0x80 != 0 {
            HeaderType::Type2
        } else {
            HeaderType::Type1
        };
        let context_flag = byte & 0x40 != 0;
        let transport_type = if byte & 0x20 != 0 {
            TransportType::Transport
        } else {
            TransportType::Broadcast
        };
        let dest_type =
            DestinationType::try_from((byte >> 3) & 0x03).map_err(|_| PacketError::InvalidFlags)?;
        let packet_type =
            PacketType::try_from(byte & 0x03).map_err(|_| PacketError::InvalidFlags)?;

        Ok(Self {
            header_type,
            context_flag,
            transport_type,
            dest_type,
            packet_type,
        })
    }
}

/// Packet parsing/construction errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// Packet too short
    TooShort,
    /// Packet too long
    TooLong,
    /// Invalid flags byte
    InvalidFlags,
    /// Invalid context byte
    InvalidContext,
    /// Payload too large
    PayloadTooLarge,
}

/// A Reticulum packet (unpacked form)
#[derive(Debug)]
pub struct Packet {
    /// Packet flags
    pub flags: PacketFlags,
    /// Hop count
    pub hops: u8,
    /// Transport ID (only for Header Type 2)
    pub transport_id: Option<[u8; TRUNCATED_HASHBYTES]>,
    /// Destination hash
    pub destination_hash: [u8; TRUNCATED_HASHBYTES],
    /// Packet context
    pub context: PacketContext,
    /// Payload data (may be encrypted)
    pub data: PacketData,
}

/// Packet data storage
#[derive(Debug)]
pub enum PacketData {
    /// Borrowed data (for parsing)
    #[cfg(feature = "alloc")]
    Owned(alloc::vec::Vec<u8>),
    /// Fixed-size inline buffer for no_std
    Inline {
        buffer: [u8; MDU],
        len: usize,
    },
}

impl PacketData {
    /// Get the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        match self {
            #[cfg(feature = "alloc")]
            PacketData::Owned(v) => v,
            PacketData::Inline { buffer, len } => &buffer[..*len],
        }
    }

    /// Get the data length
    pub fn len(&self) -> usize {
        match self {
            #[cfg(feature = "alloc")]
            PacketData::Owned(v) => v.len(),
            PacketData::Inline { len, .. } => *len,
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Packet {
    /// Calculate the header size based on header type
    pub fn header_size(&self) -> usize {
        match self.flags.header_type {
            HeaderType::Type1 => HEADER_MINSIZE,
            HeaderType::Type2 => HEADER_MAXSIZE,
        }
    }

    /// Calculate the total packed size
    pub fn packed_size(&self) -> usize {
        2 + self.header_size() + 1 + self.data.len()
    }

    /// Pack the packet into a byte buffer
    pub fn pack(&self, output: &mut [u8]) -> Result<usize, PacketError> {
        let size = self.packed_size();
        if output.len() < size {
            return Err(PacketError::TooShort);
        }
        if size > MTU {
            return Err(PacketError::TooLong);
        }

        let mut pos = 0;

        // Flags
        output[pos] = self.flags.to_byte();
        pos += 1;

        // Hops
        output[pos] = self.hops;
        pos += 1;

        // Header
        if self.flags.header_type == HeaderType::Type2 {
            if let Some(ref tid) = self.transport_id {
                output[pos..pos + TRUNCATED_HASHBYTES].copy_from_slice(tid);
                pos += TRUNCATED_HASHBYTES;
            } else {
                return Err(PacketError::InvalidFlags);
            }
        }
        output[pos..pos + TRUNCATED_HASHBYTES].copy_from_slice(&self.destination_hash);
        pos += TRUNCATED_HASHBYTES;

        // Context
        output[pos] = self.context as u8;
        pos += 1;

        // Data
        let data = self.data.as_slice();
        output[pos..pos + data.len()].copy_from_slice(data);
        pos += data.len();

        Ok(pos)
    }

    /// Unpack a packet from bytes
    #[cfg(feature = "alloc")]
    pub fn unpack(raw: &[u8]) -> Result<Self, PacketError> {
        if raw.len() < HEADER_MINSIZE + 2 {
            return Err(PacketError::TooShort);
        }
        if raw.len() > MTU {
            return Err(PacketError::TooLong);
        }

        let mut pos = 0;

        // Flags
        let flags = PacketFlags::from_byte(raw[pos])?;
        pos += 1;

        // Hops
        let hops = raw[pos];
        pos += 1;

        // Header
        let transport_id = if flags.header_type == HeaderType::Type2 {
            if raw.len() < HEADER_MAXSIZE + 2 {
                return Err(PacketError::TooShort);
            }
            let mut tid = [0u8; TRUNCATED_HASHBYTES];
            tid.copy_from_slice(&raw[pos..pos + TRUNCATED_HASHBYTES]);
            pos += TRUNCATED_HASHBYTES;
            Some(tid)
        } else {
            None
        };

        let mut destination_hash = [0u8; TRUNCATED_HASHBYTES];
        destination_hash.copy_from_slice(&raw[pos..pos + TRUNCATED_HASHBYTES]);
        pos += TRUNCATED_HASHBYTES;

        // Context
        let context =
            PacketContext::try_from(raw[pos]).map_err(|_| PacketError::InvalidContext)?;
        pos += 1;

        // Data
        let data = PacketData::Owned(raw[pos..].to_vec());

        Ok(Self {
            flags,
            hops,
            transport_id,
            destination_hash,
            context,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_roundtrip() {
        let flags = PacketFlags {
            header_type: HeaderType::Type1,
            context_flag: false,
            transport_type: TransportType::Broadcast,
            dest_type: DestinationType::Single,
            packet_type: PacketType::Data,
        };

        let byte = flags.to_byte();
        let decoded = PacketFlags::from_byte(byte).unwrap();

        assert_eq!(decoded.header_type as u8, flags.header_type as u8);
        assert_eq!(decoded.context_flag, flags.context_flag);
        assert_eq!(decoded.transport_type as u8, flags.transport_type as u8);
        assert_eq!(decoded.dest_type as u8, flags.dest_type as u8);
        assert_eq!(decoded.packet_type as u8, flags.packet_type as u8);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_packet_pack_unpack() {
        let packet = Packet {
            flags: PacketFlags {
                header_type: HeaderType::Type1,
                context_flag: false,
                transport_type: TransportType::Broadcast,
                dest_type: DestinationType::Single,
                packet_type: PacketType::Data,
            },
            hops: 0,
            transport_id: None,
            destination_hash: [0x42; TRUNCATED_HASHBYTES],
            context: PacketContext::None,
            data: PacketData::Owned(b"Hello".to_vec()),
        };

        let mut buffer = [0u8; MTU];
        let size = packet.pack(&mut buffer).unwrap();

        let unpacked = Packet::unpack(&buffer[..size]).unwrap();
        assert_eq!(unpacked.hops, packet.hops);
        assert_eq!(unpacked.destination_hash, packet.destination_hash);
        assert_eq!(unpacked.data.as_slice(), b"Hello");
    }
}

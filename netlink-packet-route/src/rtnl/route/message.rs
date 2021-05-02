use crate::{
    nlas::route::Nla,
    traits::{Emitable, Parseable},
    DecodeError,
    RouteHeader,
    RouteMessageBuffer,
};
use anyhow::Context;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct RouteMessage {
    pub header: RouteHeader,
    pub nlas: Vec<Nla>,
}

impl Emitable for RouteMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<RouteMessageBuffer<&'a T>> for RouteMessage {
    fn parse(buf: &RouteMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        Ok(RouteMessage {
            header: RouteHeader::parse(buf).context("failed to parse route message header")?,
            nlas: Vec::<Nla>::parse(buf).context("failed to parse route message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<RouteMessageBuffer<&'a T>> for Vec<Nla> {
    fn parse(buf: &RouteMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}

impl RouteMessage {
    /// Returns the input interface index, if present.
    pub fn input_interface(&self) -> Option<u32> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Iif(v) = nla {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Returns the output interface index, if present.
    pub fn output_interface(&self) -> Option<u32> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Oif(v) = nla {
                Some(*v)
            } else {
                None
            }
        })
    }

    /// Returns the source address prefix, if present.
    pub fn source_prefix(&self) -> Option<(IpAddr, u8)> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Source(v) = nla {
                Some((*v, self.header.source_prefix_length))
            } else {
                None
            }
        })
    }

    /// Returns the destination subnet prefix, if present.
    pub fn destination_prefix(&self) -> Option<(IpAddr, u8)> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Destination(v) = nla {
                Some((*v, self.header.destination_prefix_length))
            } else {
                None
            }
        })
    }

    /// Returns the gateway address, if present.
    pub fn gateway(&self) -> Option<IpAddr> {
        self.nlas.iter().find_map(|nla| {
            if let Nla::Gateway(v) = nla {
                Some(*v)
            } else {
                None
            }
        })
    }
}

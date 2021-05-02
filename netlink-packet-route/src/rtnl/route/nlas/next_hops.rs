use crate::{
    traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NextHops {
    pub len: u16,
    pub flags: u8,
    pub hops: u8,
    pub interface_id: u32,
}

pub const NEXT_HOPS_LEN: usize = 64;

buffer!(NextHopsBuffer(NEXT_HOPS_LEN) {
    len: (u16, 0..2),
    flags: (u8, 2),
    hops: (u8, 3),
    interface_id: (u32, 4..8),
});

impl<T: AsRef<[u8]>> Parseable<NextHopsBuffer<T>> for NextHops {
    fn parse(buf: &NextHopsBuffer<T>) -> Result<NextHops, DecodeError> {
        Ok(NextHops {
            len: buf.len(),
            flags: buf.flags(),
            hops: buf.hops(),
            interface_id: buf.interface_id(),
        })
    }
}

impl Emitable for NextHops {
    fn buffer_len(&self) -> usize {
        NEXT_HOPS_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut buffer = NextHopsBuffer::new(buffer);
        buffer.set_len(self.len);
        buffer.set_flags(self.flags);
        buffer.set_hops(self.hops);
        buffer.set_interface_id(self.interface_id);
    }
}

use std::io;

pub trait ReadExt: io::Read {
    fn read_u8(&mut self) -> io::Result<u8>;

    fn read_u16_be(&mut self) -> io::Result<u16>;

    fn read_u32_be(&mut self) -> io::Result<u32>;
}

impl<T> ReadExt for T
where
    T: io::Read,
{
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut byte = [0];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    fn read_u16_be(&mut self) -> io::Result<u16> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32_be(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }
}

pub trait CursorExt {
    fn peek(&mut self) -> io::Result<u8>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn peek(&mut self) -> io::Result<u8> {
        self.get_ref()
            .get(self.position() as usize)
            .copied()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "attempted to peek on an exhausted cursor",
                )
            })
    }
}

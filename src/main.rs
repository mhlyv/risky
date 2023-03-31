use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Magic([u8; 4]),
    FieldRead(&'static str, std::io::Error),
    Bitness(u8),
    Endianness(u8),
}

#[derive(Debug, Clone, Copy)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl TryFrom<u8> for Bitness {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        Ok(match val {
            1 => Self::Bits32,
            2 => Self::Bits64,
            _ => return Err(Error::Bitness(val)),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Usize {
    U32(u32),
    U64(u64),
}

macro_rules! usize_into {
    ($($ty:ty),+) => {
        $(impl Into<$ty> for Usize {
            fn into(self) -> $ty {
                match self {
                    Self::U32(x) => x as $ty,
                    Self::U64(x) => x as $ty,
                }
            }
        })*
    }
}

usize_into!(u64, usize);

#[derive(Debug, Clone, Copy)]
pub enum Endianness {
    Little,
    Big,
}

impl TryFrom<u8> for Endianness {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        Ok(match val {
            1 => Self::Little,
            2 => Self::Big,
            _ => return Err(Error::Endianness(val)),
        })
    }
}

/// Read a single byte from reader
fn read_byte<R: Read>(reader: &mut R, field: &'static str) -> Result<u8, Error> {
    let mut tmp = [0u8; 1];

    reader
        .read_exact(&mut tmp)
        .map(|_| tmp[0])
        .map_err(|x| Error::FieldRead(field, x))
}

/// Read a field of N bytes from a reader
fn read_bytes<R: Read, const N: usize>(
    reader: &mut R,
    field: &'static str,
) -> Result<[u8; N], Error> {
    let mut tmp = [0u8; N];

    reader
        .read_exact(&mut tmp)
        .map(|_| tmp)
        .map_err(|x| Error::FieldRead(field, x))
}

/// Read a type from a reader with a given endianness
macro_rules! read_type {
    ($reader:expr, $type:ty, $endianness:expr, $field:expr) => {
        read_bytes::<_, { std::mem::size_of::<$type>() }>($reader, $field).map(|bytes| {
            match $endianness {
                Endianness::Little => <$type>::from_le_bytes(bytes),
                Endianness::Big => <$type>::from_be_bytes(bytes),
            }
        })
    };
}

/// Read an appropriate address type for the platform
fn read_usize<R: Read>(
    reader: &mut R,
    bitness: Bitness,
    endianness: Endianness,
    field: &'static str,
) -> Result<Usize, Error> {
    Ok(match bitness {
        Bitness::Bits32 => Usize::U32(read_type!(reader, u32, endianness, field)?),
        Bitness::Bits64 => Usize::U64(read_type!(reader, u64, endianness, field)?),
    })
}

const LOADABLE_SEGMENT: u32 = 1;

fn read_elf(path: impl AsRef<Path>) -> Result<(), Error> {
    let mut reader = BufReader::new(File::open(path).map_err(Error::Io)?);

    let magic = read_bytes::<_, 4>(&mut reader, "magic")?;
    if &magic != b"\x7fELF" {
        return Err(Error::Magic(magic));
    }

    let bitness = read_byte(&mut reader, "bitness")?;
    let bitness = Bitness::try_from(bitness)?;

    let endianness = read_byte(&mut reader, "endianness")?;
    let endianness = Endianness::try_from(endianness)?;

    let _ = read_byte(&mut reader, "version")?;
    let _ = read_byte(&mut reader, "abi")?;
    let _ = read_byte(&mut reader, "abi version")?;
    let _ = read_bytes::<_, 7>(&mut reader, "padding")?;
    let _ = read_type!(&mut reader, u16, endianness, "type")?;
    let _ = read_type!(&mut reader, u16, endianness, "machine")?;
    let _ = read_type!(&mut reader, u32, endianness, "ELF version")?;

    let entry = read_usize(&mut reader, bitness, endianness, "entry")?;
    let program_header_offset =
        read_usize(&mut reader, bitness, endianness, "program header offset")?;

    let _ = read_usize(&mut reader, bitness, endianness, "section header offset")?;
    let _ = read_type!(&mut reader, u32, endianness, "flags")?;
    let _ = read_type!(&mut reader, u16, endianness, "ELF header size")?;
    let _ = read_type!(&mut reader, u16, endianness, "program header entry size")?;

    let program_header_entries =
        read_type!(&mut reader, u16, endianness, "program header entries")?;

    reader
        .seek(SeekFrom::Start(program_header_offset.into()))
        .map_err(Error::Io)?;

    let mut load = Vec::new();

    for _ in 0..program_header_entries {
        let segment_type = read_type!(&mut reader, u32, endianness, "segment type")?;

        let flags = if matches!(bitness, Bitness::Bits64) {
            read_type!(&mut reader, u32, endianness, "segment flags for 64 bit")?
        } else {
            0
        };

        let offset = read_usize(&mut reader, bitness, endianness, "segment offset")?.into();
        let virtual_address =
            read_usize(&mut reader, bitness, endianness, "segment virtual address")?;
        let _ = read_usize(&mut reader, bitness, endianness, "segment physcal address")?;
        let file_size =
            read_usize(&mut reader, bitness, endianness, "segment size in file")?.into();
        let memory_size =
            read_usize(&mut reader, bitness, endianness, "segment size in memory")?.into();

        // only care about non zero sized segments
        if memory_size == 0 {
            continue;
        }

        let flags = if matches!(bitness, Bitness::Bits32) {
            read_type!(&mut reader, u32, endianness, "segment flags for 32 bit")?
        } else {
            flags
        };

        let _ = read_usize(&mut reader, bitness, endianness, "segment alignment")?;

        // only care about loadable segments
        if segment_type != LOADABLE_SEGMENT {
            continue;
        }

        let data = if file_size > 0 {
            // save current position in file
            let stream_position = reader.stream_position().map_err(Error::Io)?;

            // seek to segment data
            reader.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;

            // read segment data
            let mut data = vec![0; file_size];
            reader.read_exact(&mut data).map_err(Error::Io)?;

            // reset position in file
            reader
                .seek(SeekFrom::Start(stream_position))
                .map_err(Error::Io)?;

            data
        } else {
            vec![0; memory_size]
        };

        load.push((virtual_address, data));
    }

    for (addr, data) in load {
        println!("{:#10x?} {:#x}", addr, data.len());
    }

    Ok(())
}

fn main() {
    let path = std::env::args().nth(1).expect("excpected filename");

    read_elf(path).unwrap();
}

mod elf;

use elf::{Protection, Segment};
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum Error {
    InsertOverlap {
        new: usize,
        overlapping: Vec<usize>,
    },
    SliceOutOfBounds {
        addr: usize,
        len: usize,
    },
    Protection {
        addr: usize,
        available: Protection,
        required: Protection,
    },
    UnmappedAddress(usize),
}

#[derive(Debug, Default)]
pub struct MMU {
    segments: BTreeMap<usize, Segment>,
}

impl MMU {
    fn try_from_iter<T: IntoIterator<Item = Segment>>(iter: T) -> Result<Self, Error> {
        let mut mmu = Self::default();

        for segment in iter {
            mmu.insert(segment)?;
        }

        Ok(mmu)
    }

    fn check_protection(
        addr: usize,
        available: Protection,
        required: Protection,
    ) -> Result<(), Error> {
        if required & available == required {
            Ok(())
        } else {
            Err(Error::Protection {
                addr,
                available,
                required,
            })
        }
    }

    pub fn read(&self, addr: usize) -> Result<u8, Error> {
        let segment = self.get_segment(addr)?;
        let i = addr - segment.start;

        Self::check_protection(
            addr,
            segment.protection,
            Protection {
                r: true,
                w: false,
                x: false,
            },
        )?;

        Ok(segment.data[i])
    }

    pub fn read_slice(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error> {
        let segment = self.get_segment(addr)?;
        let len = buf.len();
        let i = addr - segment.start;

        Self::check_protection(
            addr,
            segment.protection,
            Protection {
                r: true,
                w: false,
                x: false,
            },
        )?;

        if addr + len > segment.start + segment.data.len() {
            return Err(Error::SliceOutOfBounds { addr, len });
        }

        buf.copy_from_slice(&segment.data[i..i + len]);

        Ok(())
    }

    pub fn write(&mut self, addr: usize, val: u8) -> Result<(), Error> {
        let segment = self.get_mut_segment(addr)?;
        let i = addr - segment.start;

        Self::check_protection(
            addr,
            segment.protection,
            Protection {
                r: false,
                w: true,
                x: false,
            },
        )?;

        segment.data[i] = val;

        Ok(())
    }

    pub fn write_slice(&mut self, addr: usize, buf: &[u8]) -> Result<(), Error> {
        let segment = self.get_mut_segment(addr)?;
        let len = buf.len();
        let i = addr - segment.start;

        Self::check_protection(
            addr,
            segment.protection,
            Protection {
                r: false,
                w: true,
                x: false,
            },
        )?;

        if addr + len > segment.start + segment.data.len() {
            return Err(Error::SliceOutOfBounds { addr, len });
        }

        segment.data[i..i + len].copy_from_slice(buf);

        Ok(())
    }

    /// get the keys of segments that would overlap the segment (new, len)
    fn get_overlapping(&self, new: usize, len: usize) -> Vec<usize> {
        // IMPORTANT
        // this assumes that there are no existing overlaps between segments
        // that can only happen if a segment wasn't mapped with the `insert` function

        let mut overlapping = Vec::new();

        // get the overlap from a previous segment
        // | old |
        //   | new |
        let remaining_range = if let Ok(segment) = self.get_segment(new) {
            overlapping.push(segment.start);
            segment.start + segment.data.len()..new + len
        } else {
            new..new + len
        };

        // get the overlas from segments starting further
        //   | old | | old |
        // |    new    |
        overlapping.extend(self.segments.range(remaining_range).map(|(&i, _)| i));

        overlapping
    }

    fn insert(&mut self, segment: Segment) -> Result<(), Error> {
        // ignore zero sized segments
        if segment.data.is_empty() {
            return Ok(());
        }

        let overlapping = self.get_overlapping(segment.start, segment.data.len());

        if overlapping.is_empty() {
            self.segments.insert(segment.start, segment);
            Ok(())
        } else {
            Err(Error::InsertOverlap {
                overlapping,
                new: segment.start,
            })
        }
    }

    /// Get the key of the segment containing the address
    fn get_segment_key(&self, addr: usize) -> Option<usize> {
        self.segments
            .range(..=addr)
            .last()
            .and_then(|(&key, last)| {
                // check if the last segment in long enough
                if addr >= last.start && addr < last.start + last.data.len() {
                    Some(key)
                } else {
                    None
                }
            })
    }

    /// get the segment which the address is in
    fn get_segment(&self, addr: usize) -> Result<&Segment, Error> {
        self.get_segment_key(addr)
            .and_then(|key| self.segments.get(&key))
            .ok_or(Error::UnmappedAddress(addr))
    }

    /// get the segment which the address is in
    fn get_mut_segment(&mut self, addr: usize) -> Result<&mut Segment, Error> {
        self.get_segment_key(addr)
            .and_then(|key| self.segments.get_mut(&key))
            .ok_or(Error::UnmappedAddress(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_possible() {
        let segments = vec![
            Segment {
                start: 123,
                protection: 0.into(),
                data: vec![0; 10],
            },
            Segment {
                start: 140,
                protection: 0.into(),
                data: vec![0; 10],
            },
        ]
        .into_iter();

        let mmu = MMU::try_from_iter(segments).unwrap();

        assert!(matches!(
            mmu.get_segment(122),
            Err(Error::UnmappedAddress(..))
        ));
        assert_eq!(mmu.get_segment(123).unwrap().start, 123);
        assert_eq!(mmu.get_segment(123 + 1).unwrap().start, 123);
        assert_eq!(mmu.get_segment(123 + 9).unwrap().start, 123);
        assert!(matches!(
            mmu.get_segment(123 + 10),
            Err(Error::UnmappedAddress(..))
        ));
        assert_eq!(mmu.get_segment(140).unwrap().start, 140);
        assert_eq!(mmu.get_segment(140 + 5).unwrap().start, 140);
        assert_eq!(mmu.get_segment(140 + 9).unwrap().start, 140);
        assert!(matches!(
            mmu.get_segment(140 + 10),
            Err(Error::UnmappedAddress(..))
        ));
    }

    #[test]
    fn insert_empty() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 0,
            protection: 0.into(),
            data: vec![],
        })
        .unwrap();

        assert!(mmu.segments.is_empty());
    }

    #[test]
    fn insert() {
        let mut mmu = MMU::default();

        let segments = vec![
            Segment {
                start: 0,
                protection: 0.into(),
                data: vec![0; 10],
            },
            Segment {
                start: 10,
                protection: 0.into(),
                data: vec![0; 10],
            },
            Segment {
                start: 21,
                protection: 0.into(),
                data: vec![0; 10],
            },
        ]
        .into_iter();

        for segment in segments {
            mmu.insert(segment).unwrap();
        }

        assert_eq!(mmu.segments.len(), 3);
    }

    #[test]
    fn insert_overlap_left() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 0,
            protection: 0.into(),
            data: vec![0; 10],
        })
        .unwrap();

        assert!(matches!(
            mmu.insert(Segment {
                start: 9,
                protection: 0.into(),
                data: vec![0; 10],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_overlap_right() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 9,
            protection: 0.into(),
            data: vec![0; 10],
        })
        .unwrap();

        assert!(matches!(
            mmu.insert(Segment {
                start: 0,
                protection: 0.into(),
                data: vec![0; 10],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_overlap_inside() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1,
            protection: 0.into(),
            data: vec![0; 9],
        })
        .unwrap();

        assert!(matches!(
            mmu.insert(Segment {
                start: 0,
                protection: 0.into(),
                data: vec![0; 10],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_overlap_left_and_right() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 0,
            protection: 0.into(),
            data: vec![0; 10],
        })
        .unwrap();

        assert!(matches!(
            mmu.insert(Segment {
                start: 1,
                protection: 0.into(),
                data: vec![0; 9],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_multi_left_and_right() {
        let mut mmu = MMU::default();

        let segments = vec![
            Segment {
                start: 0,
                protection: 0.into(),
                data: vec![0; 10],
            },
            Segment {
                start: 20,
                protection: 0.into(),
                data: vec![0; 10],
            },
        ]
        .into_iter();

        for segment in segments {
            mmu.insert(segment).unwrap();
        }

        assert!(matches!(
            mmu.insert(Segment {
                start: 9,
                protection: 0.into(),
                data: vec![0; 11],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn read() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![111],
        })
        .unwrap();

        assert_eq!(mmu.read(1234).unwrap(), 111);
    }

    #[test]
    fn read_protection() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0.into(),
            data: vec![111],
        })
        .unwrap();

        assert!(matches!(mmu.read(1234), Err(Error::Protection { .. })));
    }

    #[test]
    fn read_unmapped() {
        let mmu = MMU::default();

        assert!(matches!(mmu.read(1234), Err(Error::UnmappedAddress(..))));
    }

    #[test]
    fn read_slice() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        let mut buf = [0; 3];

        mmu.read_slice(1234 + 1, &mut buf).unwrap();

        assert_eq!(buf, [2, 3, 4]);
    }

    #[test]
    fn read_slice_protection() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        let mut buf = [0; 3];

        assert!(matches!(
            mmu.read_slice(1234 + 1, &mut buf),
            Err(Error::Protection { .. })
        ));
    }

    #[test]
    fn read_slice_unmapped() {
        let mmu = MMU::default();

        let mut buf = [0; 3];

        assert!(matches!(
            mmu.read_slice(1234, &mut buf),
            Err(Error::UnmappedAddress(..))
        ));
    }

    #[test]
    fn read_slice_oob() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        let mut buf = [0; 7];

        assert!(matches!(
            mmu.read_slice(1234, &mut buf),
            Err(Error::SliceOutOfBounds { .. }),
        ));
    }

    #[test]
    fn write() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0],
        })
        .unwrap();

        mmu.write(1234, 1).unwrap();
        assert!(matches!(mmu.read(1234), Ok(1)));
    }

    #[test]
    fn write_protection() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b100.into(),
            data: vec![0],
        })
        .unwrap();

        assert!(matches!(mmu.write(1234, 1), Err(Error::Protection { .. })));
        assert!(matches!(mmu.read(1234), Ok(0)));
    }

    #[test]
    fn write_unmapped() {
        let mut mmu = MMU::default();

        assert!(matches!(
            mmu.write(1234, 1),
            Err(Error::UnmappedAddress(..))
        ));
    }

    #[test]
    fn write_slice() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let data = "asdasd".as_bytes();

        mmu.write_slice(1234, data).unwrap();

        let mut buf = [0; 6];
        mmu.read_slice(1234, &mut buf).unwrap();

        assert_eq!(buf, data);
    }

    #[test]
    fn write_slice_protection() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b100.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let data = "asdasd".as_bytes();

        assert!(matches!(
            mmu.write_slice(1234, data),
            Err(Error::Protection { .. })
        ));

        let mut buf = [0; 6];
        mmu.read_slice(1234, &mut buf).unwrap();

        assert_eq!(buf, [0; 6]);
    }

    #[test]
    fn write_slice_unmapped() {
        let mut mmu = MMU::default();

        let data = "asdasd".as_bytes();

        assert!(matches!(
            mmu.write_slice(1234, data),
            Err(Error::UnmappedAddress { .. })
        ));
    }

    #[test]
    fn write_slice_oob() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let data = &[1; 7];

        assert!(matches!(
            mmu.write_slice(1234, data),
            Err(Error::SliceOutOfBounds { .. })
        ));

        let mut buf = [0; 6];
        mmu.read_slice(1234, &mut buf).unwrap();

        assert_eq!(buf, [0; 6]);
    }

    #[test]
    fn no_overlaps() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let overlapping = mmu.get_overlapping(0, 1234);

        assert_eq!(overlapping.len(), 0);
    }

    #[test]
    fn single_overlap() {
        let mut mmu = MMU::default();

        mmu.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let overlapping = mmu.get_overlapping(0, 1235);
        assert_eq!(overlapping.len(), 1);

        let overlapping = mmu.get_overlapping(1234 + 6 - 1, 10);
        assert_eq!(overlapping.len(), 1);
    }

    #[test]
    fn multiple_overlap() {
        let mut mmu = MMU::default();

        let segments = vec![
            Segment {
                start: 10,
                protection: 0.into(),
                data: vec![0; 3],
            },
            Segment {
                start: 20,
                protection: 0.into(),
                data: vec![0; 3],
            },
            Segment {
                start: 30,
                protection: 0.into(),
                data: vec![0; 3],
            },
        ]
        .into_iter();

        for segment in segments {
            mmu.insert(segment).unwrap();
        }

        let overlapping = mmu.get_overlapping(12, 10);
        assert_eq!(overlapping.len(), 2);

        let overlapping = mmu.get_overlapping(0, 21);
        assert_eq!(overlapping.len(), 2);

        let overlapping = mmu.get_overlapping(22, 10);
        assert_eq!(overlapping.len(), 2);

        let overlapping = mmu.get_overlapping(19, 100);
        assert_eq!(overlapping.len(), 2);

        let overlapping = mmu.get_overlapping(20, 12);
        assert_eq!(overlapping.len(), 2);

        let overlapping = mmu.get_overlapping(0, 100);
        assert_eq!(overlapping.len(), 3);

        let overlapping = mmu.get_overlapping(10, 100);
        assert_eq!(overlapping.len(), 3);

        let overlapping = mmu.get_overlapping(12, 100);
        assert_eq!(overlapping.len(), 3);

        let overlapping = mmu.get_overlapping(12, 32 - 12 + 1);
        assert_eq!(overlapping.len(), 3);
    }
}

fn main() {
    // let path = std::env::args().nth(1).expect("excpected filename");
    let path = "samples/exit";

    let elf = elf::read_elf(path).unwrap();

    let segments = elf.segments.into_iter();
    let mmu = MMU::try_from_iter(segments).unwrap();

    println!("{:#?}", mmu);

    let mut buf = [0; 4];
    mmu.read_slice(elf.entry.into(), &mut buf).unwrap();
    println!("{:x?}", buf);
}

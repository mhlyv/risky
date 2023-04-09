mod elf;

use elf::{Protection, Segment};
use std::collections::BTreeMap;

#[derive(Debug)]
pub enum Error {
    InsertOverlap {
        old: usize,
        new: usize,
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

    fn get_overlapping(&self, new: &Segment) -> Option<&Segment> {
        // from left
        // | old |
        //     | new |
        let left = self
            .segments
            .range(..=new.start)
            .last()
            .and_then(|(_, old)| {
                if old.start + old.data.len() > new.start {
                    Some(old)
                } else {
                    None
                }
            });

        if left.is_some() {
            return left;
        }

        // from right
        //     | old |
        // | new |
        let right = self
            .segments
            .range(new.start..)
            .next()
            .and_then(|(_, old)| {
                if old.start < new.start + new.data.len() {
                    Some(old)
                } else {
                    None
                }
            });

        if right.is_some() {
            return right;
        }

        // fully inside
        //  | old |
        // |  new  |
        let inside = self
            .segments
            .range(new.start..new.start + new.data.len())
            .next()
            .map(|(_, s)| s);

        if inside.is_some() {
            return inside;
        }

        None
    }

    fn insert(&mut self, segment: Segment) -> Result<(), Error> {
        // ignore zero sized segments
        if segment.data.is_empty() {
            return Ok(());
        }

        if let Some(overlapping) = self.get_overlapping(&segment) {
            Err(Error::InsertOverlap {
                old: overlapping.start,
                new: segment.start,
            })
        } else {
            self.segments.insert(segment.start, segment);
            Ok(())
        }
    }

    /// Get the key of the segment containing the address
    fn get_segment_key(&self, addr: usize) -> Result<usize, Error> {
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
            .ok_or_else(|| Error::UnmappedAddress(addr))
    }

    /// get the segment which the address is in
    fn get_segment(&self, addr: usize) -> Result<&Segment, Error> {
        let key = self.get_segment_key(addr)?;
        self.segments
            .get(&key)
            // could unwrap here maybe
            .ok_or_else(|| Error::UnmappedAddress(addr))
    }

    /// get the segment which the address is in
    fn get_mut_segment(&mut self, addr: usize) -> Result<&mut Segment, Error> {
        let key = self.get_segment_key(addr)?;
        self.segments
            .get_mut(&key)
            // could unwrap here maybe
            .ok_or_else(|| Error::UnmappedAddress(addr))
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
            Err(Error::InsertOverlap { old: 0, new: 9 })
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
            Err(Error::InsertOverlap { old: 9, new: 0 })
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
            Err(Error::InsertOverlap { old: 1, new: 0 })
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
            Err(Error::InsertOverlap { old: 0, new: 1 })
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
            Err(Error::InsertOverlap { old: _, new: _ })
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

use crate::elf::{Protection, Segment};
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

/// A Segmented Virtual Memory implementation
#[derive(Debug, Default)]
pub struct VirtualMemory {
    segments: BTreeMap<usize, Segment>,
}

impl VirtualMemory {
    pub fn try_from_iter<T: IntoIterator<Item = Segment>>(iter: T) -> Result<Self, Error> {
        let mut vm = Self::default();

        for segment in iter {
            vm.insert(segment)?;
        }

        Ok(vm)
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

    /// get the sorted keys of segments that would overlap the segment (new, len)
    fn get_overlapping(&self, new: usize, len: usize) -> Vec<usize> {
        // IMPORTANT
        // this assumes that there are no existing overlaps between segments
        // that can only happen if a segment wasn't mapped with the `insert` function

        let mut overlapping = Vec::new();

        let end = new + len;

        // get the overlap from a previous segment
        // | old |
        //   | new |
        let remaining_range = if let Ok(segment) = self.get_segment(new) {
            overlapping.push(segment.start);
            let segment_end = segment.start + segment.data.len();

            // prevent a negative range
            if segment_end < end {
                segment_end..end
            } else {
                end..end
            }
        } else {
            new..end
        };

        // get the overlas from segments starting further
        //   | old | | old |
        // |    new    |
        overlapping.extend(self.segments.range(remaining_range).map(|(&i, _)| i));

        // make sure the results are sorted
        debug_assert_eq!(overlapping, {
            let mut clone = overlapping.clone();
            clone.sort();
            clone
        });

        overlapping
    }

    pub fn insert(&mut self, segment: Segment) -> Result<(), Error> {
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

    fn resize_or_unmap_or_split_segment(&mut self, key: usize, del_start: usize, del_len: usize) {
        let segment = self.segments.get(&key).unwrap();
        let (orig_start, orig_len) = (segment.start, segment.data.len());
        let (del_end, orig_end) = (del_start + del_len, orig_start + orig_len);

        if del_start <= orig_start && del_end >= orig_end {
            // if there is a total overlap just remove the segment
            self.segments.remove(&key);
        } else if del_start <= orig_start || del_end >= orig_end {
            // if there is an overlap remove, resize, then reinsert
            let mut segment = self.segments.remove(&key).unwrap();

            let (keep_range, new_start) = if orig_start < del_start {
                // |   old   |
                // | keep |  del  |
                (0..del_start - orig_start, orig_start)
            } else {
                //    |    old    |
                // | del |  keep  |
                (del_end - orig_start..orig_len, del_end)
            };

            // keep slice of data
            segment.data = segment.data.drain(keep_range).collect();

            // set start
            segment.start = new_start;

            // it's safe to not use the `vm::insert` function here, because the mappings
            // didn't change since we unmapped the original one
            self.segments.insert(segment.start, segment);
        } else if del_start > orig_start && del_end < orig_end {
            // if an inner slice needs to get unmapped: remove, split, reinsert
            let segment = self.segments.remove(&key).unwrap();

            let head = Segment {
                start: segment.start,
                protection: segment.protection,
                data: Vec::from(&segment.data[0..del_start - orig_start]),
            };

            let tail = Segment {
                start: del_end,
                protection: segment.protection,
                data: Vec::from(&segment.data[del_end - orig_start..]),
            };

            // it's safe to not use the `vm::insert` function here, because the mappings
            // didn't change since we unmapped the original one
            self.segments.insert(head.start, head);
            self.segments.insert(tail.start, tail);
        }
    }

    /// unmap a region defined by (start, len)
    pub fn unmap(&mut self, start: usize, len: usize) -> Result<(), Error> {
        let overlapping = self.get_overlapping(start, len);

        match overlapping.len() {
            0 => Ok(()),
            1 => {
                self.resize_or_unmap_or_split_segment(overlapping[0], start, len);
                Ok(())
            }
            _ => {
                self.resize_or_unmap_or_split_segment(overlapping[0], start, len);
                self.resize_or_unmap_or_split_segment(
                    overlapping[overlapping.len() - 1],
                    start,
                    len,
                );

                // the segments between the last and first overlap get entirely unmapped
                for key in &overlapping[1..overlapping.len() - 1] {
                    self.segments.remove(key).unwrap();
                }

                Ok(())
            }
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

        let vm = VirtualMemory::try_from_iter(segments).unwrap();

        assert!(matches!(
            vm.get_segment(122),
            Err(Error::UnmappedAddress(..))
        ));
        assert_eq!(vm.get_segment(123).unwrap().start, 123);
        assert_eq!(vm.get_segment(123 + 1).unwrap().start, 123);
        assert_eq!(vm.get_segment(123 + 9).unwrap().start, 123);
        assert!(matches!(
            vm.get_segment(123 + 10),
            Err(Error::UnmappedAddress(..))
        ));
        assert_eq!(vm.get_segment(140).unwrap().start, 140);
        assert_eq!(vm.get_segment(140 + 5).unwrap().start, 140);
        assert_eq!(vm.get_segment(140 + 9).unwrap().start, 140);
        assert!(matches!(
            vm.get_segment(140 + 10),
            Err(Error::UnmappedAddress(..))
        ));
    }

    #[test]
    fn insert_empty() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 0,
            protection: 0.into(),
            data: vec![],
        })
        .unwrap();

        assert!(vm.segments.is_empty());
    }

    #[test]
    fn insert() {
        let mut vm = VirtualMemory::default();

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
            vm.insert(segment).unwrap();
        }

        assert_eq!(vm.segments.len(), 3);
    }

    #[test]
    fn insert_overlap_left() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 0,
            protection: 0.into(),
            data: vec![0; 10],
        })
        .unwrap();

        assert!(matches!(
            vm.insert(Segment {
                start: 9,
                protection: 0.into(),
                data: vec![0; 10],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_overlap_right() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 9,
            protection: 0.into(),
            data: vec![0; 10],
        })
        .unwrap();

        assert!(matches!(
            vm.insert(Segment {
                start: 0,
                protection: 0.into(),
                data: vec![0; 10],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_overlap_inside() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1,
            protection: 0.into(),
            data: vec![0; 9],
        })
        .unwrap();

        assert!(matches!(
            vm.insert(Segment {
                start: 0,
                protection: 0.into(),
                data: vec![0; 10],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_overlap_left_and_right() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 0,
            protection: 0.into(),
            data: vec![0; 10],
        })
        .unwrap();

        assert!(matches!(
            vm.insert(Segment {
                start: 1,
                protection: 0.into(),
                data: vec![0; 9],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn insert_multi_left_and_right() {
        let mut vm = VirtualMemory::default();

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
            vm.insert(segment).unwrap();
        }

        assert!(matches!(
            vm.insert(Segment {
                start: 9,
                protection: 0.into(),
                data: vec![0; 11],
            }),
            Err(Error::InsertOverlap { .. })
        ));
    }

    #[test]
    fn read() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![111],
        })
        .unwrap();

        assert_eq!(vm.read(1234).unwrap(), 111);
    }

    #[test]
    fn read_protection() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0.into(),
            data: vec![111],
        })
        .unwrap();

        assert!(matches!(vm.read(1234), Err(Error::Protection { .. })));
    }

    #[test]
    fn read_unmapped() {
        let vm = VirtualMemory::default();

        assert!(matches!(vm.read(1234), Err(Error::UnmappedAddress(..))));
    }

    #[test]
    fn read_slice() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        let mut buf = [0; 3];

        vm.read_slice(1234 + 1, &mut buf).unwrap();

        assert_eq!(buf, [2, 3, 4]);
    }

    #[test]
    fn read_slice_protection() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        let mut buf = [0; 3];

        assert!(matches!(
            vm.read_slice(1234 + 1, &mut buf),
            Err(Error::Protection { .. })
        ));
    }

    #[test]
    fn read_slice_unmapped() {
        let vm = VirtualMemory::default();

        let mut buf = [0; 3];

        assert!(matches!(
            vm.read_slice(1234, &mut buf),
            Err(Error::UnmappedAddress(..))
        ));
    }

    #[test]
    fn read_slice_oob() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        let mut buf = [0; 7];

        assert!(matches!(
            vm.read_slice(1234, &mut buf),
            Err(Error::SliceOutOfBounds { .. }),
        ));
    }

    #[test]
    fn write() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0],
        })
        .unwrap();

        vm.write(1234, 1).unwrap();
        assert!(matches!(vm.read(1234), Ok(1)));
    }

    #[test]
    fn write_protection() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b100.into(),
            data: vec![0],
        })
        .unwrap();

        assert!(matches!(vm.write(1234, 1), Err(Error::Protection { .. })));
        assert!(matches!(vm.read(1234), Ok(0)));
    }

    #[test]
    fn write_unmapped() {
        let mut vm = VirtualMemory::default();

        assert!(matches!(vm.write(1234, 1), Err(Error::UnmappedAddress(..))));
    }

    #[test]
    fn write_slice() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let data = "asdasd".as_bytes();

        vm.write_slice(1234, data).unwrap();

        let mut buf = [0; 6];
        vm.read_slice(1234, &mut buf).unwrap();

        assert_eq!(buf, data);
    }

    #[test]
    fn write_slice_protection() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b100.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let data = "asdasd".as_bytes();

        assert!(matches!(
            vm.write_slice(1234, data),
            Err(Error::Protection { .. })
        ));

        let mut buf = [0; 6];
        vm.read_slice(1234, &mut buf).unwrap();

        assert_eq!(buf, [0; 6]);
    }

    #[test]
    fn write_slice_unmapped() {
        let mut vm = VirtualMemory::default();

        let data = "asdasd".as_bytes();

        assert!(matches!(
            vm.write_slice(1234, data),
            Err(Error::UnmappedAddress { .. })
        ));
    }

    #[test]
    fn write_slice_oob() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let data = &[1; 7];

        assert!(matches!(
            vm.write_slice(1234, data),
            Err(Error::SliceOutOfBounds { .. })
        ));

        let mut buf = [0; 6];
        vm.read_slice(1234, &mut buf).unwrap();

        assert_eq!(buf, [0; 6]);
    }

    #[test]
    fn no_overlaps() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let overlapping = vm.get_overlapping(0, 1234);

        assert_eq!(overlapping.len(), 0);
    }

    #[test]
    fn single_overlap() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        let overlapping = vm.get_overlapping(0, 1235);
        assert_eq!(overlapping.len(), 1);

        let overlapping = vm.get_overlapping(1234 + 6 - 1, 10);
        assert_eq!(overlapping.len(), 1);
    }

    #[test]
    fn multiple_overlap() {
        let mut vm = VirtualMemory::default();

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
            vm.insert(segment).unwrap();
        }

        let overlapping = vm.get_overlapping(12, 10);
        assert_eq!(overlapping.len(), 2);

        let overlapping = vm.get_overlapping(0, 21);
        assert_eq!(overlapping.len(), 2);

        let overlapping = vm.get_overlapping(22, 10);
        assert_eq!(overlapping.len(), 2);

        let overlapping = vm.get_overlapping(19, 100);
        assert_eq!(overlapping.len(), 2);

        let overlapping = vm.get_overlapping(20, 12);
        assert_eq!(overlapping.len(), 2);

        let overlapping = vm.get_overlapping(0, 100);
        assert_eq!(overlapping.len(), 3);

        let overlapping = vm.get_overlapping(10, 100);
        assert_eq!(overlapping.len(), 3);

        let overlapping = vm.get_overlapping(12, 100);
        assert_eq!(overlapping.len(), 3);

        let overlapping = vm.get_overlapping(12, 32 - 12 + 1);
        assert_eq!(overlapping.len(), 3);
    }

    #[test]
    fn unmap_none() {
        let mut vm = VirtualMemory::default();
        assert!(vm.unmap(1234, 1234).is_ok());
    }

    #[test]
    fn unmap_exact() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        assert!(vm.unmap(1234, 6).is_ok());
        assert_eq!(vm.segments.len(), 0);
    }

    #[test]
    fn unmap_overlap_whole() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![0; 6],
        })
        .unwrap();

        assert!(vm.unmap(0, 10000).is_ok());
        assert_eq!(vm.segments.len(), 0);
    }

    #[test]
    fn unmap_head() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        assert!(vm.unmap(0, 1234 + 5).is_ok());
        assert_eq!(vm.segments.len(), 1);
        let (&key, segment) = vm.segments.first_key_value().unwrap();
        assert_eq!(key, 1234 + 5);
        assert_eq!(segment.start, 1234 + 5);
        assert_eq!(segment.data, &[6]);
    }

    #[test]
    fn unmap_tail() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        assert!(vm.unmap(1234 + 5, 1000).is_ok());
        assert_eq!(vm.segments.len(), 1);
        let (&key, segment) = vm.segments.first_key_value().unwrap();
        assert_eq!(key, 1234);
        assert_eq!(segment.start, 1234);
        assert_eq!(segment.data, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn unmap_inside() {
        let mut vm = VirtualMemory::default();

        vm.insert(Segment {
            start: 1234,
            protection: 0b111.into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
        .unwrap();

        assert!(vm.unmap(1234 + 2, 2).is_ok());
        assert_eq!(vm.segments.len(), 2);
        let mut it = vm.segments.iter();

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 1234);
        assert_eq!(segment.start, 1234);
        assert_eq!(segment.data, &[1, 2]);

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 1234 + 4);
        assert_eq!(segment.start, 1234 + 4);
        assert_eq!(segment.data, &[5, 6]);
    }

    #[test]
    fn unmap_multiple_exact() {
        let mut vm = VirtualMemory::default();

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
            vm.insert(segment).unwrap();
        }

        assert!(vm.unmap(10, 23).is_ok());
        assert_eq!(vm.segments.len(), 0);
    }

    #[test]
    fn unmap_multiple_head() {
        let mut vm = VirtualMemory::default();

        let segments = vec![
            Segment {
                start: 10,
                protection: 0.into(),
                data: vec![1, 2, 3],
            },
            Segment {
                start: 20,
                protection: 0.into(),
                data: vec![4, 5, 6],
            },
            Segment {
                start: 30,
                protection: 0.into(),
                data: vec![7, 8, 9],
            },
        ]
        .into_iter();

        for segment in segments {
            vm.insert(segment).unwrap();
        }

        assert!(vm.unmap(0, 22).is_ok());
        assert_eq!(vm.segments.len(), 2);

        let mut it = vm.segments.iter();

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 22);
        assert_eq!(segment.start, 22);
        assert_eq!(segment.data, &[6]);

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 30);
        assert_eq!(segment.start, 30);
        assert_eq!(segment.data, &[7, 8, 9]);
    }

    #[test]
    fn unmap_multiple_tail() {
        let mut vm = VirtualMemory::default();

        let segments = vec![
            Segment {
                start: 10,
                protection: 0.into(),
                data: vec![1, 2, 3],
            },
            Segment {
                start: 20,
                protection: 0.into(),
                data: vec![4, 5, 6],
            },
            Segment {
                start: 30,
                protection: 0.into(),
                data: vec![7, 8, 9],
            },
        ]
        .into_iter();

        for segment in segments {
            vm.insert(segment).unwrap();
        }

        assert!(vm.unmap(0, 12).is_ok());
        assert_eq!(vm.segments.len(), 3);

        let mut it = vm.segments.iter();

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 12);
        assert_eq!(segment.start, 12);
        assert_eq!(segment.data, &[3]);

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 20);
        assert_eq!(segment.start, 20);
        assert_eq!(segment.data, &[4, 5, 6]);

        let (&key, segment) = it.next().unwrap();
        assert_eq!(key, 30);
        assert_eq!(segment.start, 30);
        assert_eq!(segment.data, &[7, 8, 9]);
    }
}

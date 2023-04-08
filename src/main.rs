mod elf;

use elf::Segment;
use std::collections::BTreeMap;

#[derive(Debug)]
enum Error {
    InsertOverlap { old: usize, new: usize },
}

#[derive(Debug, Default)]
struct MMU {
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

    fn segment_including_address(&self, addr: usize) -> Option<&Segment> {
        self.segments.range(..=addr).last().and_then(|(_, last)| {
            // check if the last segment in long enough
            if addr >= last.start && addr < last.start + last.data.len() {
                Some(last)
            } else {
                None
            }
        })
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

        println!("{:#?}", mmu);

        assert!(mmu.segment_including_address(122).is_none());
        assert_eq!(mmu.segment_including_address(123).unwrap().start, 123);
        assert_eq!(mmu.segment_including_address(123 + 1).unwrap().start, 123);
        assert_eq!(mmu.segment_including_address(123 + 9).unwrap().start, 123);
        assert!(mmu.segment_including_address(123 + 10).is_none());
        assert_eq!(mmu.segment_including_address(140).unwrap().start, 140);
        assert_eq!(mmu.segment_including_address(140 + 5).unwrap().start, 140);
        assert_eq!(mmu.segment_including_address(140 + 9).unwrap().start, 140);
        assert!(mmu.segment_including_address(140 + 10).is_none());
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
}

fn main() {
    // let path = std::env::args().nth(1).expect("excpected filename");
    let path = "samples/exit";

    let elf = elf::read_elf(path).unwrap();

    let segments = elf.segments.into_iter();
    let mmu = MMU::try_from_iter(segments).unwrap();

    println!("{:#?}", mmu);
}

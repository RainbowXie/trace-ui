//! Fixed-layout working storage; these are resource bounds, not output limits.
use crate::error::{Result, TraceError};
const WORK_BYTES: usize = 8 * 1024 * 1024;
fn resource() -> TraceError {
    TraceError::Internal("function facts working memory resource limit exceeded".into())
}

pub(super) struct Fixed<T> {
    pub(super) values: Vec<T>,
    capacity: usize,
}
impl<T> Fixed<T> {
    pub(super) fn new() -> Result<Self> {
        Self::with_bytes(WORK_BYTES)
    }
    fn with_bytes(bytes: usize) -> Result<Self> {
        let capacity = bytes / std::mem::size_of::<T>();
        let mut values = Vec::new();
        values.try_reserve_exact(capacity).map_err(|_| resource())?;
        if values
            .capacity()
            .checked_mul(std::mem::size_of::<T>())
            .filter(|n| *n <= bytes)
            .is_none()
        {
            return Err(resource());
        }
        Ok(Self { values, capacity })
    }
    pub(super) fn insert(&mut self, pos: usize, value: T) -> Result<()> {
        if self.values.len() == self.capacity {
            return Err(resource());
        }
        self.values.insert(pos, value);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Cell {
    pub(super) address: u64,
    pub(super) seq: u32,
    pub(super) value: Option<u8>,
}
impl Fixed<Cell> {
    pub(super) fn apply(&mut self, address: u64, value: Option<u8>, seq: u32) -> Result<()> {
        let cell = Cell {
            address,
            value,
            seq,
        };
        match self.values.binary_search_by_key(&address, |c| c.address) {
            Ok(pos) => self.values[pos] = cell,
            Err(pos) => self.insert(pos, cell)?,
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) struct Dependency {
    pub(super) seq: u32,
    pub(super) expanded: bool,
}
impl Fixed<Dependency> {
    pub(super) fn seed(&mut self, seq: u32) -> Result<()> {
        match self.values.binary_search_by_key(&seq, |d| d.seq) {
            Ok(_) => Ok(()),
            Err(pos) => self.insert(
                pos,
                Dependency {
                    seq,
                    expanded: false,
                },
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_cells_replace_unknown_and_refuse_new_address() {
        let mut cells = Fixed::<Cell>::with_bytes(2 * std::mem::size_of::<Cell>()).unwrap();
        for seq in 0..100 {
            cells.apply(10, Some(7), seq).unwrap();
        }
        cells.apply(10, None, 101).unwrap();
        assert_eq!(cells.values[0].value, None);
        assert_eq!(cells.values[0].seq, 101);
        cells.apply(11, Some(8), 102).unwrap();
        assert!(matches!(
            cells.apply(12, None, 103),
            Err(TraceError::Internal(_))
        ));
        assert_eq!(cells.values.len(), 2);
        let mut deps =
            Fixed::<Dependency>::with_bytes(2 * std::mem::size_of::<Dependency>()).unwrap();
        deps.seed(10).unwrap();
        deps.seed(10).unwrap();
        deps.seed(20).unwrap();
        assert!(deps.seed(30).is_err());
        assert_eq!(deps.values.len(), 2);
    }
}

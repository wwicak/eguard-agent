use std::collections::{HashSet, VecDeque};

const CAPACITY: usize = 4096;
#[derive(Default)]
pub(super) struct IncompleteDedup {
    pack: [u8; 32],
    seen: HashSet<[u8; 32]>,
    fifo: VecDeque<[u8; 32]>,
}
impl IncompleteDedup {
    pub(super) fn activate(&mut self, pack: [u8; 32]) {
        if self.pack != pack {
            self.seen.clear();
            self.fifo.clear();
            self.pack = pack;
        }
    }
    /// FIFO dedup is intentionally reset on pack changes/restart; evicted files may re-alert.
    pub(super) fn insert(&mut self, pack: [u8; 32], file: [u8; 32]) -> (bool, bool) {
        self.activate(pack);
        if !self.seen.insert(file) {
            return (false, false);
        }
        self.fifo.push_back(file);
        let evicted = self.seen.len() > CAPACITY;
        if evicted {
            if let Some(oldest) = self.fifo.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        (true, evicted)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_file_emits_once_and_pack_change_reemits() {
        let mut state = IncompleteDedup::default();
        assert_eq!(state.insert([1; 32], [2; 32]), (true, false));
        assert_eq!(state.insert([1; 32], [2; 32]), (false, false));
        assert_eq!(state.insert([3; 32], [2; 32]), (true, false));
        assert_eq!(state.seen.len(), 1);
    }
    #[test]
    fn capacity_4096_evicts_once_and_old_file_reemits() {
        let mut state = IncompleteDedup::default();
        let mut evictions = 0;
        for index in 0..4097u64 {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&index.to_le_bytes());
            let (new, evicted) = state.insert([1; 32], digest);
            assert!(new);
            evictions += usize::from(evicted);
            assert!(state.seen.len() <= 4096);
        }
        assert_eq!(evictions, 1);
        assert_eq!(state.fifo.len(), 4096);
        assert_eq!(state.insert([1; 32], [0; 32]), (true, true));
    }
}

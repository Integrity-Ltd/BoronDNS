//! Persistent main-directory maps. The experiment keeps root cloning bounded
//! while reducing the unrelated keys copied when one zone is published.
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(not(feature = "experimental-directory-shards"))]
pub(super) type DirectoryShards<K, V> = [Arc<HashMap<K, V>>; super::ZONE_DIRECTORY_SHARD_COUNT];
#[cfg(all(test, not(feature = "experimental-directory-shards")))]
pub(super) const ROOT_OWNER_COUNT: usize = super::ZONE_DIRECTORY_SHARD_COUNT;
#[cfg(not(feature = "experimental-directory-shards"))]
pub(super) const MAP_COUNT: usize = super::ZONE_DIRECTORY_SHARD_COUNT;

#[cfg(feature = "experimental-directory-shards")]
const GROUP_SIZE: usize = 64;
#[cfg(feature = "experimental-directory-shards")]
pub(super) const ROOT_OWNER_COUNT: usize = 64;
#[cfg(feature = "experimental-directory-shards")]
pub(super) const MAP_COUNT: usize = ROOT_OWNER_COUNT * GROUP_SIZE;

#[cfg(feature = "experimental-directory-shards")]
type Group<K, V> = [Arc<HashMap<K, V>>; GROUP_SIZE];

#[cfg(feature = "experimental-directory-shards")]
#[derive(Debug, Clone)]
pub(super) struct DirectoryShards<K, V> {
    groups: [Arc<Group<K, V>>; ROOT_OWNER_COUNT],
}

pub(super) fn new_directory_shards<K, V>() -> DirectoryShards<K, V> {
    #[cfg(not(feature = "experimental-directory-shards"))]
    {
        std::array::from_fn(|_| Arc::new(HashMap::new()))
    }
    #[cfg(feature = "experimental-directory-shards")]
    {
        // Empty publications need not allocate thousands of empty maps. Every
        // mutation first obtains a private group and then a private map.
        let empty = Arc::new(HashMap::new());
        let group = Arc::new(std::array::from_fn(|_| empty.clone()));
        DirectoryShards {
            groups: std::array::from_fn(|_| group.clone()),
        }
    }
}

#[cfg(feature = "experimental-directory-shards")]
impl<K, V> DirectoryShards<K, V> {
    pub(super) fn iter(&self) -> impl Iterator<Item = &Arc<HashMap<K, V>>> {
        self.groups.iter().flat_map(|group| group.iter())
    }

    #[cfg(all(test, feature = "experimental-serving-directory"))]
    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Arc<HashMap<K, V>>> {
        self.groups
            .iter_mut()
            .flat_map(|group| Arc::make_mut(group).iter_mut())
    }
}

#[cfg(feature = "experimental-directory-shards")]
impl<K, V> std::ops::Index<usize> for DirectoryShards<K, V> {
    type Output = Arc<HashMap<K, V>>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.groups[index / GROUP_SIZE][index % GROUP_SIZE]
    }
}

#[cfg(feature = "experimental-directory-shards")]
impl<K, V> std::ops::IndexMut<usize> for DirectoryShards<K, V> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut Arc::make_mut(&mut self.groups[index / GROUP_SIZE])[index % GROUP_SIZE]
    }
}

#[cfg(all(test, feature = "experimental-directory-shards"))]
mod tests {
    use super::*;

    #[test]
    fn directory_shards_cow_preserves_other_maps_and_frozen_roots() {
        let mut maps = new_directory_shards();
        for index in 0..MAP_COUNT {
            Arc::make_mut(&mut maps[index]).insert(index, index);
        }
        let old = maps.clone();
        for index in [0, 63, 64, 2048, MAP_COUNT - 1] {
            Arc::make_mut(&mut maps[index]).insert(index, MAP_COUNT);
            assert_eq!(old[index][&index], index);
            assert_eq!(maps[index][&index], MAP_COUNT);
        }
        let changed = (0..MAP_COUNT)
            .filter(|&index| !Arc::ptr_eq(&old[index], &maps[index]))
            .count();
        assert_eq!(changed, 5);
        assert_eq!(maps.iter().map(|map| map.len()).sum::<usize>(), MAP_COUNT);
        assert_eq!(ROOT_OWNER_COUNT, 64);
    }

    #[test]
    fn directory_shards_empty_shared_maps_do_not_leak_mutations() {
        let mut maps = new_directory_shards();
        let old = maps.clone();
        Arc::make_mut(&mut maps[7]).insert("zone", 1);
        assert!(old.iter().all(|map| map.is_empty()));
        assert_eq!(maps.iter().filter(|map| !map.is_empty()).count(), 1);
        let next = maps.clone();
        Arc::make_mut(&mut maps[7]).remove("zone");
        assert_eq!(next[7]["zone"], 1);
        assert!(maps.iter().all(|map| map.is_empty()));
    }
}

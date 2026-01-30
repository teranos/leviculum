//! File-based storage for persistent data

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Storage manager for persistent data
pub struct Storage {
    /// Base directory for all storage
    base_path: PathBuf,
}

impl Storage {
    /// Create a new storage manager
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create directories if they don't exist
        std::fs::create_dir_all(&base_path)
            .map_err(|e| Error::Storage(format!("Failed to create storage dir: {e}")))?;

        Ok(Self { base_path })
    }

    /// Get the base path
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Get path for a specific storage category
    pub fn category_path(&self, category: &str) -> PathBuf {
        self.base_path.join(category)
    }

    /// Ensure a category directory exists
    pub fn ensure_category(&self, category: &str) -> Result<PathBuf> {
        let path = self.category_path(category);
        std::fs::create_dir_all(&path)
            .map_err(|e| Error::Storage(format!("Failed to create category dir: {e}")))?;
        Ok(path)
    }

    /// Read raw bytes from storage
    pub fn read_raw(&self, category: &str, name: &str) -> Result<Vec<u8>> {
        let path = self.category_path(category).join(name);
        std::fs::read(&path)
            .map_err(|e| Error::Storage(format!("Failed to read {}: {e}", path.display())))
    }

    /// Write raw bytes to storage
    pub fn write_raw(&self, category: &str, name: &str, data: &[u8]) -> Result<()> {
        let category_path = self.ensure_category(category)?;
        let path = category_path.join(name);

        // Write to temp file first, then rename (atomic on most systems)
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, data)
            .map_err(|e| Error::Storage(format!("Failed to write temp file: {e}")))?;
        std::fs::rename(&temp_path, &path)
            .map_err(|e| Error::Storage(format!("Failed to rename temp file: {e}")))?;

        Ok(())
    }

    /// Read msgpack-serialized data
    pub fn read<T: serde::de::DeserializeOwned>(&self, category: &str, name: &str) -> Result<T> {
        let data = self.read_raw(category, name)?;
        rmp_serde::from_slice(&data)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize: {e}")))
    }

    /// Write msgpack-serialized data
    pub fn write<T: serde::Serialize>(&self, category: &str, name: &str, value: &T) -> Result<()> {
        let data = rmp_serde::to_vec(value)
            .map_err(|e| Error::Serialization(format!("Failed to serialize: {e}")))?;
        self.write_raw(category, name, &data)
    }

    /// Check if a file exists
    pub fn exists(&self, category: &str, name: &str) -> bool {
        self.category_path(category).join(name).exists()
    }

    /// Delete a file
    pub fn delete(&self, category: &str, name: &str) -> Result<()> {
        let path = self.category_path(category).join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| Error::Storage(format!("Failed to delete {}: {e}", path.display())))?;
        }
        Ok(())
    }

    /// List files in a category
    pub fn list(&self, category: &str) -> Result<Vec<String>> {
        let path = self.category_path(category);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let entries = std::fs::read_dir(&path)
            .map_err(|e| Error::Storage(format!("Failed to read dir: {e}")))?;

        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| Error::Storage(format!("Failed to read entry: {e}")))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }

        Ok(names)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl reticulum_core::traits::Storage for Storage {
    fn load(&self, category: &str, key: &[u8]) -> Option<Vec<u8>> {
        let name = hex_encode(key);
        self.read_raw(category, &name).ok()
    }

    fn store(
        &mut self,
        category: &str,
        key: &[u8],
        value: &[u8],
    ) -> std::result::Result<(), reticulum_core::traits::StorageError> {
        let name = hex_encode(key);
        self.write_raw(category, &name, value)
            .map_err(|_| reticulum_core::traits::StorageError::IoError)
    }

    fn delete(
        &mut self,
        category: &str,
        key: &[u8],
    ) -> std::result::Result<(), reticulum_core::traits::StorageError> {
        let name = hex_encode(key);
        Storage::delete(self, category, &name)
            .map_err(|_| reticulum_core::traits::StorageError::NotFound)
    }

    fn list_keys(&self, category: &str) -> Vec<Vec<u8>> {
        self.list(category)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| hex_decode(&s))
            .collect()
    }
}

/// Storage categories used by Reticulum
pub mod categories {
    pub const IDENTITIES: &str = "identities";
    pub const DESTINATIONS: &str = "destinations";
    pub const RATCHETS: &str = "ratchets";
    pub const CACHE: &str = "cache";
    pub const RESOURCES: &str = "resources";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn temp_storage() -> Storage {
        let path = temp_dir().join(format!("reticulum_test_{}", std::process::id()));
        Storage::new(&path).unwrap()
    }

    #[test]
    fn test_raw_storage() {
        let storage = temp_storage();

        storage.write_raw("test", "data.bin", b"hello").unwrap();
        let data = storage.read_raw("test", "data.bin").unwrap();
        assert_eq!(data, b"hello");

        // Cleanup
        storage.delete("test", "data.bin").unwrap();
    }

    #[test]
    fn test_serialized_storage() {
        let storage = temp_storage();

        let value = vec![1u32, 2, 3, 4, 5];
        storage.write("test", "numbers.mp", &value).unwrap();

        let loaded: Vec<u32> = storage.read("test", "numbers.mp").unwrap();
        assert_eq!(loaded, value);

        // Cleanup
        storage.delete("test", "numbers.mp").unwrap();
    }

    #[test]
    fn test_exists() {
        let storage = temp_storage();

        assert!(!storage.exists("test", "nonexistent"));

        storage.write_raw("test", "exists.bin", b"data").unwrap();
        assert!(storage.exists("test", "exists.bin"));

        // Cleanup
        storage.delete("test", "exists.bin").unwrap();
    }

    #[test]
    fn test_core_storage_trait() {
        use reticulum_core::traits::Storage as CoreStorage;

        let mut storage = temp_storage();
        let key = [0x01, 0x02, 0x03];

        // Store via trait
        CoreStorage::store(&mut storage, "core_test", &key, b"trait_value").unwrap();

        // Load via trait
        let data = CoreStorage::load(&storage, "core_test", &key);
        assert_eq!(data, Some(b"trait_value".to_vec()));

        // Exists via trait
        assert!(CoreStorage::exists(&storage, "core_test", &key));

        // List keys via trait
        let keys = CoreStorage::list_keys(&storage, "core_test");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], key.to_vec());

        // Delete via trait
        CoreStorage::delete(&mut storage, "core_test", &key).unwrap();
        assert!(!CoreStorage::exists(&storage, "core_test", &key));
    }
}

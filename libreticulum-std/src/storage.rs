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
            .map_err(|e| Error::Storage(format!("Failed to create storage dir: {}", e)))?;

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
            .map_err(|e| Error::Storage(format!("Failed to create category dir: {}", e)))?;
        Ok(path)
    }

    /// Read raw bytes from storage
    pub fn read_raw(&self, category: &str, name: &str) -> Result<Vec<u8>> {
        let path = self.category_path(category).join(name);
        std::fs::read(&path)
            .map_err(|e| Error::Storage(format!("Failed to read {}: {}", path.display(), e)))
    }

    /// Write raw bytes to storage
    pub fn write_raw(&self, category: &str, name: &str, data: &[u8]) -> Result<()> {
        let category_path = self.ensure_category(category)?;
        let path = category_path.join(name);

        // Write to temp file first, then rename (atomic on most systems)
        let temp_path = path.with_extension("tmp");
        std::fs::write(&temp_path, data)
            .map_err(|e| Error::Storage(format!("Failed to write temp file: {}", e)))?;
        std::fs::rename(&temp_path, &path)
            .map_err(|e| Error::Storage(format!("Failed to rename temp file: {}", e)))?;

        Ok(())
    }

    /// Read msgpack-serialized data
    pub fn read<T: serde::de::DeserializeOwned>(&self, category: &str, name: &str) -> Result<T> {
        let data = self.read_raw(category, name)?;
        rmp_serde::from_slice(&data)
            .map_err(|e| Error::Serialization(format!("Failed to deserialize: {}", e)))
    }

    /// Write msgpack-serialized data
    pub fn write<T: serde::Serialize>(&self, category: &str, name: &str, value: &T) -> Result<()> {
        let data = rmp_serde::to_vec(value)
            .map_err(|e| Error::Serialization(format!("Failed to serialize: {}", e)))?;
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
                .map_err(|e| Error::Storage(format!("Failed to delete {}: {}", path.display(), e)))?;
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
            .map_err(|e| Error::Storage(format!("Failed to read dir: {}", e)))?;

        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| Error::Storage(format!("Failed to read entry: {}", e)))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }

        Ok(names)
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
        let path = temp_dir().join(format!("leviculum_test_{}", std::process::id()));
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
}

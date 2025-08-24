pub mod memory;
pub mod sqlite;
pub mod manager;

// Exportar componentes principales
pub use manager::{StorageManager, StorageConfig, StorageType};
pub use memory::{MemoryStorage, MemoryStorageConfig};
pub use sqlite::SqliteStorage;

// Re-exportar utilidades de configuración
pub use manager::config;
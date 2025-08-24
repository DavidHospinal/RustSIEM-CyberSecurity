# 🦀 RustSIEM - Guía de Compilación y Ejecución

## 📋 Requisitos Previos

### 1. Instalación de Rust
```bash
# Instalar Rust y Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verificar instalación
rustc --version
cargo --version
```

### 2. Dependencias del Sistema
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential pkg-config libssl-dev

# CentOS/RHEL/Fedora
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel

# macOS (con Homebrew)
brew install openssl
```

## 🔧 Preparación del Proyecto

### 1. Verificar Estructura del Proyecto
```bash
cd rust_siem
ls -la src/
```

Debe contener:
- `main.rs` - Punto de entrada principal
- `lib.rs` - Biblioteca principal con tipos
- `detector/` - Módulos de detección
- `storage/` - Gestión de almacenamiento
- `alerting/` - Sistema de alertas
- `dashboard/` - Frontend web y APIs
- `parser/` - Parsers de logs

### 2. Verificar Dependencias
```bash
cat Cargo.toml
```

## 🚀 Compilación

### 1. Verificación Básica
```bash
# Verificar que el código compila sin errores
cargo check

# Ver warnings detallados
cargo check --verbose
```

### 2. Compilación de Desarrollo
```bash
# Compilación rápida para desarrollo
cargo build

# Ejecutar después de compilar
./target/debug/rust_siem --help
```

### 3. Compilación de Producción
```bash
# Compilación optimizada
cargo build --release

# Ejecutar versión optimizada
./target/release/rust_siem --help
```

## 🏃‍♂️ Ejecución

### 1. Configuración Básica
```bash
# Crear directorio de logs (si no existe)
mkdir -p logs

# Crear archivo de configuración básica
cat > config.yaml << EOF
detection_rules:
  sql_injection:
    enabled: true
    threshold: 0.7
  xss:
    enabled: true  
    threshold: 0.7
  brute_force:
    enabled: true
    max_attempts: 5
    time_window_minutes: 10

ml_config:
  enabled: true
  model_type: "isolation_forest"
  training_window_hours: 24
  anomaly_threshold: 0.5

alerting:
  email:
    enabled: false
  webhooks: []
EOF
```

### 2. Ejecutar el SIEM
```bash
# Ejecutar con configuración por defecto
cargo run

# O especificar parámetros
cargo run -- --port 8080 --config config.yaml --log-dir ./logs
```

### 3. Opciones de Línea de Comandos
```bash
# Ver todas las opciones disponibles
cargo run -- --help

# Opciones principales:
# --port, -p          Puerto del dashboard web (default: 8080)
# --config, -c        Archivo de configuración (default: config.yaml)
# --log-dir, -l       Directorio de logs (default: ./logs)
# --log-level         Nivel de logging (default: info)
```

## 🌐 Acceso al Dashboard

Una vez ejecutado, el dashboard estará disponible en:
- **URL Principal**: http://localhost:8080
- **API de Estadísticas**: http://localhost:8080/api/stats
- **API de Eventos**: http://localhost:8080/api/events
- **API de Alertas**: http://localhost:8080/api/alerts

### Páginas Disponibles:
- `/` - Dashboard principal con métricas en tiempo real
- `/events` - Página de eventos con filtros avanzados
- `/alerts` - Centro de alertas de seguridad

## 🔍 Resolución de Problemas

### 1. Errores de Compilación Comunes

#### Error: "failed to resolve dependencies"
```bash
# Limpiar cache de Cargo
cargo clean

# Actualizar dependencias
cargo update

# Reinstalar dependencias
rm Cargo.lock
cargo build
```

#### Error: "linker not found"
```bash
# Instalar herramientas de compilación
# Ubuntu/Debian:
sudo apt install build-essential

# CentOS/RHEL:
sudo yum groupinstall "Development Tools"
```

#### Error: "SSL/TLS related"
```bash
# Ubuntu/Debian:
sudo apt install libssl-dev pkg-config

# CentOS/RHEL:
sudo yum install openssl-devel
```

### 2. Problemas de Ejecución

#### Puerto ocupado
```bash
# Usar puerto diferente
cargo run -- --port 8081
```

#### Permisos de archivos
```bash
# Asegurar permisos de escritura
chmod 755 logs/
chmod 644 config.yaml
```

### 3. Debugging

#### Ejecutar con logs detallados
```bash
# Nivel debug
cargo run -- --log-level debug

# O con variables de entorno
RUST_LOG=debug cargo run
```

#### Verificar funcionalidad paso a paso
```bash
# 1. Solo verificar compilación
cargo check

# 2. Ejecutar tests (si existen)
cargo test

# 3. Ejecutar con configuración mínima
cargo run
```

## 📊 Monitoreo y Logs

### Variables de Entorno Útiles
```bash
# Nivel de logs detallado
export RUST_LOG=debug

# Logs de SQLite
export RUST_LOG=sqlx=debug

# Logs específicos del SIEM
export RUST_LOG=rust_siem=debug
```

### Archivos de Log
- Los logs del sistema aparecen en la consola
- Los eventos procesados se almacenan en memoria/SQLite
- Los errores se muestran con stack traces detallados

## 🏗️ Desarrollo

### Estructura de Desarrollo
```bash
# Ejecutar en modo desarrollo con auto-recarga
cargo watch -x run

# Formatear código
cargo fmt

# Ejecutar linter
cargo clippy

# Generar documentación
cargo doc --open
```

### Variables de Entorno de Desarrollo
```bash
# Configurar storage tipo
export RUSTSIEM_STORAGE_TYPE=memory

# Configurar base de datos
export RUSTSIEM_DB_PATH=./dev.db

# Configurar límites
export RUSTSIEM_MAX_EVENTS=10000
```

## 🚨 Notas Importantes

1. **Primera Ejecución**: El sistema creará automáticamente la base de datos SQLite si no existe
2. **Memoria**: Por defecto usa storage en memoria para desarrollo
3. **Producción**: Usar `cargo build --release` para mejor rendimiento
4. **Seguridad**: Cambiar configuraciones por defecto antes de usar en producción
5. **Backup**: Los datos en memoria se pierden al reiniciar, usar SQLite para persistencia

## 📝 Logs de Ejemplo

Al ejecutar correctamente, deberías ver:
```
INFO  rust_siem > Iniciando RustSIEM...
INFO  rust_siem::storage > Storage manager initialized with type: Memory
INFO  rust_siem::dashboard > 🚀 RustSIEM Dashboard iniciado en http://localhost:8080
INFO  rust_siem::dashboard > 📊 API endpoints disponibles:
INFO  rust_siem::dashboard >    GET /api/stats - Estadísticas del sistema
INFO  rust_siem::dashboard >    GET /api/events - Lista de eventos  
INFO  rust_siem::dashboard >    GET /api/alerts - Alertas activas
```

¡Tu RustSIEM estará listo para usar! 🎉
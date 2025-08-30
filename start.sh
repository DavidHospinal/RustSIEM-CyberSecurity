#!/bin/bash

# Establecer variables de entorno por defecto
export RUST_LOG=${RUST_LOG:-info}
export PORT=${PORT:-3030}

echo "🚀 Iniciando RustSIEM en puerto $PORT"
echo "📊 Nivel de logging: $RUST_LOG"

# Ejecutar la aplicación
exec ./target/release/rust_siem
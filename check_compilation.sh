#!/bin/bash

echo "🦀 Verificando compilación de RustSIEM..."
echo "==========================================="

# Cambiar al directorio del proyecto
cd "/mnt/d/Proyectos con IA/2025/Proy08-RustSIEM/rustsiem/rust_siem"

# Verificar si Cargo está disponible
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Cargo no está instalado o no está en el PATH"
    echo "Por favor, instala Rust y Cargo desde: https://rustup.rs/"
    exit 1
fi

echo "📦 Verificando dependencias..."
echo "Cargo.toml presente: $(test -f Cargo.toml && echo "✅" || echo "❌")"

echo ""
echo "🔍 Ejecutando cargo check..."
echo "=============================="

# Ejecutar cargo check para verificar la compilación
cargo check 2>&1 | head -50

echo ""
echo "📊 Resumen del proyecto:"
echo "======================="
echo "Archivos Rust encontrados:"
find src -name "*.rs" | wc -l
echo "Tamaño del proyecto:"
find src -name "*.rs" -exec wc -l {} + | tail -1

echo ""
echo "🗂️ Estructura de módulos:"
echo "========================"
find src -name "mod.rs" -o -name "lib.rs" -o -name "main.rs" | sort

echo ""
echo "⚙️ Para compilar completamente ejecuta:"
echo "cargo build --release"
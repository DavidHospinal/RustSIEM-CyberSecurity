# Contribuir a RustSIEM

Agradecemos tu interés en contribuir a RustSIEM. Este documento proporciona pautas e información para contribuidores.

## Tabla de Contenidos

- [Código de Conducta](#código-de-conducta)
- [Primeros Pasos](#primeros-pasos)
- [Entorno de Desarrollo](#entorno-de-desarrollo)
- [Pautas de Contribución](#pautas-de-contribución)
- [Proceso de Pull Request](#proceso-de-pull-request)
- [Consideraciones de Seguridad](#consideraciones-de-seguridad)
- [Comunidad](#comunidad)

## Código de Conducta

RustSIEM está comprometido con proporcionar un entorno acogedor e inclusivo para todos los contribuidores. Esperamos que todos los participantes adhieran a nuestro código de conducta:

- Ser respetuoso e inclusivo
- Enfocarse en retroalimentación constructiva
- Respetar opiniones y experiencias diferentes
- Mostrar empatía hacia otros miembros de la comunidad
- Usar lenguaje acogedor e inclusivo

## Primeros Pasos

### Requisitos Previos

Antes de contribuir a RustSIEM, asegúrate de tener:

- **Rust 1.70+** instalado vía [rustup](https://rustup.rs/)
- **JetBrains RustRover** (IDE recomendado para desarrollo)
- **Git** para control de versiones
- Comprensión básica de conceptos de ciberseguridad
- Familiaridad con el ecosistema Rust y programación asíncrona

### Dependencias de Desarrollo

```bash
# Instalar herramientas de desarrollo esenciales
cargo install cargo-watch cargo-audit cargo-benchcmp
rustup component add rustfmt clippy

# Instalar dependencias del sistema (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev pkg-config sqlite3
```

## Entorno de Desarrollo

### Configuración del IDE (RustRover)

RustSIEM se desarrolla usando JetBrains RustRover. Configuraciones recomendadas:

1. **Estilo de Código**: Usar `.editorconfig` del proyecto
2. **Formato Rust**: Habilitar formato al guardar
3. **Clippy**: Habilitar todos los lints
4. **Herramientas de Base de Datos**: Configurar conexión SQLite para desarrollo

### Configuración del Entorno

```bash
# Clonar el repositorio
git clone https://github.com/tuusuario/rust_siem.git
cd rust_siem

# Configurar entorno de desarrollo
export RUST_LOG=debug
export RUSTSIEM_STORAGE_TYPE=memory

# Ejecutar servidor de desarrollo con hot reload
cargo watch -x 'run -- --port 8080 --log-level debug'
```

## Pautas de Contribución

### Tipos de Contribuciones

Damos la bienvenida a los siguientes tipos de contribuciones:

- **Reportes de Errores**: Ayúdanos a identificar y corregir problemas
- **Solicitudes de Características**: Sugiere nueva funcionalidad
- **Contribuciones de Código**: Implementa características o corrige errores
- **Documentación**: Mejora o expande la documentación
- **Testing**: Agrega o mejora la cobertura de pruebas
- **Mejoras de Rendimiento**: Optimiza código existente

### Reportar Problemas

Al reportar errores o solicitar características:

1. **Buscar problemas existentes** para evitar duplicados
2. **Usar plantillas de issues** proporcionadas en el repositorio
3. **Proporcionar información detallada**:
   - Sistema operativo y versión
   - Versión de Rust (`rustc --version`)
   - Pasos para reproducir (para errores)
   - Comportamiento esperado vs actual
   - Salida de logs relevante

### Desarrollo de Características

Para nuevas características:

1. **Discutir primero**: Abre un issue para discutir la característica antes de implementar
2. **Enfoque en seguridad**: Considera implicaciones de seguridad de todos los cambios
3. **Impacto en rendimiento**: Benchmarca cambios críticos para el rendimiento
4. **Documentación**: Actualiza documentación relevante
5. **Tests**: Incluye tests comprehensivos

### Estándares de Código

#### Convenciones de Rust

- Seguir convenciones de nomenclatura de Rust (snake_case, CamelCase según corresponda)
- Usar `rustfmt` para formato consistente
- Abordar todas las advertencias de `clippy`
- Escribir código idiomático de Rust usando abstracciones de costo cero
- Preferir manejo explícito de errores sobre panics

#### Pautas Específicas de Seguridad

- **Validación de entrada**: Validar todas las entradas externas
- **Seguridad de memoria**: Aprovechar el sistema de ownership de Rust
- **Gestión de secretos**: Nunca commitear secretos o credenciales
- **Logging**: Ser cauteloso sobre registrar información sensible
- **Dependencias**: Auditar regularmente dependencias con `cargo audit`

#### Pautas de Rendimiento

- **Async/await**: Usar funciones async para operaciones I/O
- **Zero-copy**: Minimizar asignaciones innecesarias
- **Benchmarking**: Incluir benchmarks para código crítico de rendimiento
- **Uso de memoria**: Monitorear consumo de memoria en tests de larga duración

### Requisitos de Testing

Todas las contribuciones deben incluir tests apropiados:

```bash
# Ejecutar la suite de tests completa
cargo test --workspace

# Ejecutar categorías específicas de tests
cargo test --test integration_tests
cargo test --test unit_tests

# Ejecutar benchmarks
cargo bench --bench detection_benchmark

# Auditoría de seguridad
cargo audit
```

#### Categorías de Tests

- **Tests Unitarios**: Probar funciones individuales y módulos
- **Tests de Integración**: Probar interacciones entre componentes
- **Tests de Rendimiento**: Benchmarks para rutas críticas
- **Tests de Seguridad**: Validar controles de seguridad

## Proceso de Pull Request

### Antes de Enviar

1. **Actualizar tu fork**: Sincronizar con la rama main más reciente
2. **Ejecutar tests**: Asegurar que todos los tests pasen
3. **Calidad de código**: Ejecutar `cargo fmt` y `cargo clippy`
4. **Verificación de seguridad**: Ejecutar `cargo audit`
5. **Documentación**: Actualizar documentación relevante

### Checklist de Pull Request

- [ ] La rama sigue convención de nomenclatura: `feature/descripcion` o `fix/numero-issue`
- [ ] Los mensajes de commit son descriptivos y siguen conventional commits
- [ ] Todos los tests pasan (`cargo test --workspace`)
- [ ] El código está formateado (`cargo fmt`)
- [ ] No hay advertencias de clippy (`cargo clippy -- -D warnings`)
- [ ] La auditoría de seguridad pasa (`cargo audit`)
- [ ] La documentación se actualiza donde sea necesario
- [ ] CHANGELOG.md se actualiza para cambios que afecten al usuario

### Proceso de Revisión

1. **Verificaciones automáticas**: El pipeline de CI debe pasar
2. **Revisión de código**: Se requiere al menos una revisión de mantenedor
3. **Revisión de seguridad**: Los cambios sensibles en seguridad necesitan revisión especializada
4. **Revisión de rendimiento**: Los cambios críticos de rendimiento necesitan benchmarking
5. **Revisión de documentación**: Los cambios que afecten al usuario necesitan revisión de documentación

### Formato de Mensaje de Commit

Seguir la especificación Conventional Commits:

```
<tipo>[ámbito opcional]: <descripción>

[cuerpo opcional]

[pie(s) opcional(es)]
```

Tipos:
- `feat`: Nueva característica
- `fix`: Corrección de error
- `docs`: Solo cambios en documentación
- `style`: Cambios que no afectan el significado del código (formato, etc.)
- `refactor`: Cambio de código que no corrige error ni agrega característica
- `perf`: Mejora de rendimiento
- `test`: Agregar tests faltantes o corregir tests existentes
- `security`: Cambios relacionados con seguridad

Ejemplos:
```
feat(detection): agregar detección avanzada de inyección SQL
fix(dashboard): resolver timeout de conexión WebSocket
docs(api): actualizar documentación de API REST
security(auth): implementar rate limiting para endpoints de login
```

## Consideraciones de Seguridad

### Desarrollo Security-First

RustSIEM es un proyecto enfocado en seguridad. Todas las contribuciones deben considerar:

- **Modelado de amenazas**: Considerar vectores de ataque potenciales
- **Defensa en profundidad**: Implementar múltiples capas de seguridad
- **Fallar de forma segura**: Asegurar que los fallos no comprometan la seguridad
- **Principio de menor privilegio**: Minimizar derechos de acceso

### Reporte de Vulnerabilidades

Si descubres una vulnerabilidad de seguridad:

1. **NO** crear un issue público
2. **Email**: security@hospinalsystems.com con detalles
3. **Incluir**: Descripción detallada, pasos de reproducción e impacto potencial
4. **Permitir**: Tiempo razonable para correcciones antes de divulgación pública

### Proceso de Revisión de Seguridad

Los cambios sensibles en seguridad requieren:

- [ ] Análisis de modelo de amenazas
- [ ] Revisión de código enfocada en seguridad
- [ ] Testing de penetración (si aplica)
- [ ] Actualizaciones de documentación de seguridad

## Comunidad

### Canales de Comunicación

- **GitHub Issues**: Para reportes de errores y solicitudes de características
- **GitHub Discussions**: Para preguntas generales y discusiones
- **Email**: Para vulnerabilidades de seguridad y asuntos privados

### Reconocimiento

Los contribuidores son reconocidos en:

- **CONTRIBUTORS.md**: Todos los contribuidores son listados
- **Notas de release**: Las contribuciones significativas son destacadas
- **Repository insights**: GitHub automáticamente rastrea contribuciones

### Oportunidades Profesionales

Los contribuidores destacados pueden ser considerados para:

- **Oportunidades de consultoría** con H'spinal Systems
- **Oportunidades de ponencias** en conferencias de ciberseguridad
- **Colaboración** en despliegues comerciales de RustSIEM

## Flujo de Trabajo de Desarrollo

### Flujo Típico de Contribución

1. **Fork** el repositorio
2. **Crear** una rama de característica desde `main`
3. **Desarrollar** tus cambios con tests
4. **Probar** exhaustivamente en entorno de desarrollo
5. **Commit** con mensajes descriptivos
6. **Push** a tu fork
7. **Enviar** un pull request
8. **Responder** a feedback de revisión
9. **Merge** después de aprobación

### Proceso de Release

RustSIEM sigue versionado semántico:

- **Major** (X.0.0): Cambios que rompen compatibilidad
- **Minor** (0.X.0): Nuevas características, compatible hacia atrás
- **Patch** (0.0.X): Correcciones de errores, compatible hacia atrás

### Obtener Ayuda

Si necesitas asistencia:

1. **Revisar documentación** en el directorio `/docs`
2. **Buscar issues existentes** y discusiones
3. **Hacer preguntas** en GitHub Discussions
4. **Contactar mantenedores** para problemas complejos

## Licencia

Al contribuir a RustSIEM, aceptas que tus contribuciones serán licenciadas bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para detalles.

---

**¡Gracias por contribuir a RustSIEM!**

Juntos, estamos construyendo la próxima generación de herramientas de ciberseguridad memory-safe.
<img width="699" height="416" alt="hospinal-systems-logo" src="https://github.com/user-attachments/assets/5002ef7b-d23e-4e90-8864-b2a6b9b1b117" />


---

**H'spinal Systems - Soluciones Avanzadas de Ciberseguridad**  
**Construido con Rust y JetBrains RustRover**

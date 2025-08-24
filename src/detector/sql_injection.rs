use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
// Removed unused imports
use urlencoding;

/// Detector especializado en SQL Injection
#[derive(Clone)]
pub struct SqlInjectionDetector {
    patterns: Vec<SqlPattern>,
    encoding_patterns: Vec<Regex>,
    bypass_patterns: Vec<Regex>,
    confidence_weights: HashMap<String, f64>,
}

/// Representa un patrón de SQL injection con metadatos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlPattern {
    pub name: String,
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub confidence: f64,
    pub attack_type: SqlAttackType,
    pub description: String,
}

/// Tipos de ataques SQL injection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SqlAttackType {
    Union,
    Boolean,
    Time,
    Error,
    Blind,
    SecondOrder,
    NoSql,
    Stored,
}

/// Resultado del análisis de SQL injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlInjectionResult {
    pub is_detected: bool,
    pub confidence_score: f64,
    pub attack_types: Vec<SqlAttackType>,
    pub matched_patterns: Vec<String>,
    pub payload_analysis: PayloadAnalysis,
    pub risk_level: RiskLevel,
    pub mitigation_suggestions: Vec<String>,
}

/// Análisis detallado del payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysis {
    pub decoded_payload: String,
    pub encoding_detected: Vec<String>,
    pub sql_keywords: Vec<String>,
    pub special_chars: Vec<char>,
    pub comment_styles: Vec<String>,
    pub quote_variations: Vec<String>,
}

/// Nivel de riesgo del ataque
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl SqlInjectionDetector {
    pub fn new() -> Self {
        let patterns = Self::initialize_patterns();
        let encoding_patterns = Self::initialize_encoding_patterns();
        let bypass_patterns = Self::initialize_bypass_patterns();
        let confidence_weights = Self::initialize_confidence_weights();

        Self {
            patterns,
            encoding_patterns,
            bypass_patterns,
            confidence_weights,
        }
    }

    /// Analiza un input para detectar SQL injection
    pub fn analyze(&self, input: &str) -> Result<SqlInjectionResult> {
        let decoded_input = self.decode_input(input)?;
        let normalized_input = self.normalize_input(&decoded_input);

        let mut matched_patterns = Vec::new();
        let mut attack_types = Vec::new();
        let mut total_confidence = 0.0;
        let mut pattern_count = 0;

        // Analizar contra todos los patrones
        for pattern in &self.patterns {
            if pattern.regex.is_match(&normalized_input) {
                matched_patterns.push(pattern.name.clone());

                if !attack_types.contains(&pattern.attack_type) {
                    attack_types.push(pattern.attack_type.clone());
                }

                total_confidence += pattern.confidence;
                pattern_count += 1;
            }
        }

        // Análisis adicional de bypass techniques
        let bypass_confidence = self.analyze_bypass_techniques(&normalized_input);
        total_confidence += bypass_confidence;

        // Calcular confidence score final
        let confidence_score = if pattern_count > 0 {
            (total_confidence / pattern_count as f64).min(1.0)
        } else {
            0.0
        };

        // Determinar si hay detección
        let is_detected = confidence_score >= 0.3;

        // Análisis del payload
        let payload_analysis = self.analyze_payload(input, &decoded_input);

        // Determinar nivel de riesgo
        let risk_level = self.determine_risk_level(confidence_score, &attack_types, &payload_analysis);

        // Generar sugerencias de mitigación
        let mitigation_suggestions = self.generate_mitigation_suggestions(&attack_types, &payload_analysis);

        Ok(SqlInjectionResult {
            is_detected,
            confidence_score,
            attack_types,
            matched_patterns,
            payload_analysis,
            risk_level,
            mitigation_suggestions,
        })
    }

    /// Inicializa los patrones de detección
    fn initialize_patterns() -> Vec<SqlPattern> {
        let mut patterns = Vec::new();

        // UNION-based injection patterns
        patterns.push(SqlPattern {
            name: "union_select".to_string(),
            regex: Regex::new(r"(?i)\bunion\s+(?:all\s+)?select\b").unwrap(),
            confidence: 0.9,
            attack_type: SqlAttackType::Union,
            description: "UNION SELECT statement detected".to_string(),
        });

        patterns.push(SqlPattern {
            name: "union_variations".to_string(),
            regex: Regex::new(r"(?i)\b(un|uni|unio|union)(\s|\/\*.*?\*\/|\+|%20)+(al|all|se|sel|sele|selec|select)\b").unwrap(),
            confidence: 0.85,
            attack_type: SqlAttackType::Union,
            description: "Obfuscated UNION SELECT detected".to_string(),
        });

        // Boolean-based blind injection
        patterns.push(SqlPattern {
            name: "boolean_logic".to_string(),
            regex: Regex::new(r"(?i)(and|or)\s+(\d+\s*=\s*\d+)").unwrap(),
            confidence: 0.8,
            attack_type: SqlAttackType::Boolean,
            description: "Boolean-based SQL injection".to_string(),
        });

        patterns.push(SqlPattern {
            name: "tautology".to_string(),
            regex: Regex::new(r"(?i)(or|and)\s+(1\s*=\s*1|true|false)").unwrap(),
            confidence: 0.85,
            attack_type: SqlAttackType::Boolean,
            description: "Tautology-based injection".to_string(),
        });

        // Time-based blind injection
        patterns.push(SqlPattern {
            name: "time_delay_mysql".to_string(),
            regex: Regex::new(r"(?i)\b(sleep|benchmark)\s*\(\s*\d+").unwrap(),
            confidence: 0.9,
            attack_type: SqlAttackType::Time,
            description: "MySQL time delay function".to_string(),
        });

        patterns.push(SqlPattern {
            name: "time_delay_mssql".to_string(),
            regex: Regex::new(r"(?i)\bwaitfor\s+delay\s+\'\d+:\d+:\d+\'").unwrap(),
            confidence: 0.9,
            attack_type: SqlAttackType::Time,
            description: "MSSQL WAITFOR DELAY".to_string(),
        });

        patterns.push(SqlPattern {
            name: "time_delay_postgresql".to_string(),
            regex: Regex::new(r"(?i)\bpg_sleep\s*\(\s*\d+").unwrap(),
            confidence: 0.9,
            attack_type: SqlAttackType::Time,
            description: "PostgreSQL pg_sleep function".to_string(),
        });

        // Error-based injection
        patterns.push(SqlPattern {
            name: "error_functions".to_string(),
            regex: Regex::new(r"(?i)\b(extractvalue|updatexml|exp|floor|rand|count)\s*\(").unwrap(),
            confidence: 0.8,
            attack_type: SqlAttackType::Error,
            description: "Error-based injection functions".to_string(),
        });

        patterns.push(SqlPattern {
            name: "cast_conversion".to_string(),
            regex: Regex::new(r"(?i)\b(cast|convert)\s*\(\s*.*\s+as\s+").unwrap(),
            confidence: 0.7,
            attack_type: SqlAttackType::Error,
            description: "Type conversion for error generation".to_string(),
        });

        // Stacked queries
        patterns.push(SqlPattern {
            name: "stacked_queries".to_string(),
            regex: Regex::new(r";\s*(insert|update|delete|drop|create|alter|exec|execute)\s+").unwrap(),
            confidence: 0.9,
            attack_type: SqlAttackType::Stored,
            description: "Stacked query injection".to_string(),
        });

        // Information schema queries
        patterns.push(SqlPattern {
            name: "information_schema".to_string(),
            regex: Regex::new(r"(?i)\binformation_schema\.(tables|columns|schemata)").unwrap(),
            confidence: 0.85,
            attack_type: SqlAttackType::Union,
            description: "Information schema enumeration".to_string(),
        });

        // Database-specific functions
        patterns.push(SqlPattern {
            name: "mysql_functions".to_string(),
            regex: Regex::new(r"(?i)\b(version|user|database|schema|concat|group_concat|load_file|into\s+outfile)\s*\(").unwrap(),
            confidence: 0.8,
            attack_type: SqlAttackType::Union,
            description: "MySQL-specific functions".to_string(),
        });

        patterns.push(SqlPattern {
            name: "mssql_functions".to_string(),
            regex: Regex::new(r"(?i)\b(@@version|db_name|user_name|system_user|xp_cmdshell|sp_executesql)\s*").unwrap(),
            confidence: 0.85,
            attack_type: SqlAttackType::Union,
            description: "MSSQL-specific functions".to_string(),
        });

        // Comment variations
        patterns.push(SqlPattern {
            name: "sql_comments".to_string(),
            regex: Regex::new(r"(?:--|#|/\*.*?\*/)").unwrap(),
            confidence: 0.6,
            attack_type: SqlAttackType::Boolean,
            description: "SQL comment injection".to_string(),
        });

        // Hexadecimal encoding
        patterns.push(SqlPattern {
            name: "hex_encoding".to_string(),
            regex: Regex::new(r"(?i)0x[0-9a-f]+").unwrap(),
            confidence: 0.7,
            attack_type: SqlAttackType::Blind,
            description: "Hexadecimal encoded payload".to_string(),
        });

        // NoSQL injection patterns
        patterns.push(SqlPattern {
            name: "nosql_operators".to_string(),
            regex: Regex::new(r"\$(?:ne|gt|lt|gte|lte|in|nin|exists|regex|where|size)").unwrap(),
            confidence: 0.8,
            attack_type: SqlAttackType::NoSql,
            description: "NoSQL injection operators".to_string(),
        });

        patterns.push(SqlPattern {
            name: "mongodb_injection".to_string(),
            regex: Regex::new(r"(?i)\$(?:where|regex).*javascript").unwrap(),
            confidence: 0.9,
            attack_type: SqlAttackType::NoSql,
            description: "MongoDB JavaScript injection".to_string(),
        });

        patterns
    }

    /// Inicializa patrones de codificación
    fn initialize_encoding_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"%[0-9a-fA-F]{2}").unwrap(),         // URL encoding
            Regex::new(r"&#x?[0-9a-fA-F]+;").unwrap(),       // HTML entities
            Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap(),       // Hex escape
            Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap(),       // Unicode escape
            Regex::new(r"\+").unwrap(),                      // Space encoding
        ]
    }

    /// Inicializa patrones de bypass
    fn initialize_bypass_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)/\*!?\d*\s*\*/").unwrap(),      // MySQL version comments
            Regex::new(r"(?i)\s+").unwrap(),                 // Multiple spaces
            Regex::new(r"(?i)union(?:\s|/\*.*?\*/)+select").unwrap(), // Space/comment bypass
            Regex::new(r"(?i)sel\x00ect").unwrap(),          // Null byte injection
            Regex::new(r"(?i)\+").unwrap(), // String concatenation
        ]
    }

    /// Inicializa pesos de confianza
    fn initialize_confidence_weights() -> HashMap<String, f64> {
        let mut weights = HashMap::new();
        weights.insert("multiple_patterns".to_string(), 0.2);
        weights.insert("encoding_detected".to_string(), 0.15);
        weights.insert("bypass_technique".to_string(), 0.1);
        weights.insert("context_relevance".to_string(), 0.1);
        weights
    }

    /// Decodifica el input usando múltiples métodos
    fn decode_input(&self, input: &str) -> Result<String> {
        let mut decoded = input.to_string();

        // URL decoding
        decoded = urlencoding::decode(&decoded)?.into_owned();

        // HTML entity decoding
        decoded = html_escape::decode_html_entities(&decoded).into_owned();

        // Hex decoding básico
        if decoded.contains("\\x") {
            decoded = decoded.replace("\\x", "%");
            if let Ok(url_decoded) = urlencoding::decode(&decoded) {
                decoded = url_decoded.into_owned();
            }
        }

        // Unicode decoding
        if decoded.contains("\\u") {
            // Implementación básica de unicode decoding
            let unicode_regex = Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap();
            for cap in unicode_regex.captures_iter(&decoded.clone()) {
                if let Ok(code_point) = u32::from_str_radix(&cap[1], 16) {
                    if let Some(unicode_char) = char::from_u32(code_point) {
                        decoded = decoded.replace(&cap[0], &unicode_char.to_string());
                    }
                }
            }
        }

        Ok(decoded)
    }

    /// Normaliza el input para mejor detección
    fn normalize_input(&self, input: &str) -> String {
        let mut normalized = input.to_lowercase();

        // Remover espacios múltiples
        normalized = Regex::new(r"\s+").unwrap().replace_all(&normalized, " ").to_string();

        // Remover comentarios de línea
        normalized = Regex::new(r"--.*$").unwrap().replace_all(&normalized, "").to_string();

        // Normalizar comentarios de bloque
        normalized = Regex::new(r"/\*.*?\*/").unwrap().replace_all(&normalized, " ").to_string();

        normalized.trim().to_string()
    }

    /// Analiza técnicas de bypass
    fn analyze_bypass_techniques(&self, input: &str) -> f64 {
        let mut bypass_score: f64 = 0.0;

        for pattern in &self.bypass_patterns {
            if pattern.is_match(input) {
                bypass_score += 0.1;
            }
        }

        bypass_score.min(0.3) // Máximo 0.3 por bypass techniques
    }

    /// Analiza el payload en detalle
    fn analyze_payload(&self, original: &str, decoded: &str) -> PayloadAnalysis {
        let mut encoding_detected = Vec::new();
        let mut sql_keywords = Vec::new();
        let mut special_chars = Vec::new();
        let mut comment_styles = Vec::new();
        let mut quote_variations = Vec::new();

        // Detectar tipos de encoding
        for (i, pattern) in self.encoding_patterns.iter().enumerate() {
            if pattern.is_match(original) {
                encoding_detected.push(match i {
                    0 => "url_encoding".to_string(),
                    1 => "html_entities".to_string(),
                    2 => "hex_escape".to_string(),
                    3 => "unicode_escape".to_string(),
                    4 => "space_plus".to_string(),
                    _ => "unknown".to_string(),
                });
            }
        }

        // Detectar palabras clave SQL
        let sql_keywords_regex = Regex::new(r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute|declare|cast|convert|substr|substring|concat|group_concat|version|user|database|schema|table|column|from|where|order|group|having|into|values|set|join|inner|left|right|outer|on|as|like|in|exists|between|is|null|not|and|or|xor|true|false|case|when|then|else|end)\b").unwrap();

        for cap in sql_keywords_regex.captures_iter(decoded) {
            sql_keywords.push(cap[1].to_lowercase());
        }

        // Detectar caracteres especiales
        for ch in decoded.chars() {
            match ch {
                '\'' | '"' | '`' | ';' | '(' | ')' | '[' | ']' | '{' | '}' |
        '*' | '+' | '-' | '=' | '<' | '>' | '!' | '@' | '#' | '$' |
        '%' | '^' | '&' | '|' | '\\' | '/' => {
        if !special_chars.contains(&ch) {
        special_chars.push(ch);
        }
        },
        _ => {}
    }
}

// Detectar estilos de comentarios
if decoded.contains("--") {
comment_styles.push("line_comment".to_string());
}
if decoded.contains("/*") && decoded.contains("*/") {
comment_styles.push("block_comment".to_string());
}
if decoded.contains("#") {
comment_styles.push("hash_comment".to_string());
}

// Detectar variaciones de comillas
if decoded.contains('\'') {
quote_variations.push("single_quote".to_string());
}
if decoded.contains('"') {
quote_variations.push("double_quote".to_string());
}
if decoded.contains('`') {
quote_variations.push("backtick".to_string());
}

PayloadAnalysis {
decoded_payload: decoded.to_string(),
encoding_detected,
sql_keywords,
special_chars,
comment_styles,
quote_variations,
}
}

/// Determina el nivel de riesgo
fn determine_risk_level(&self, confidence: f64, attack_types: &[SqlAttackType], payload: &PayloadAnalysis) -> RiskLevel {
    if confidence >= 0.9 {
        return RiskLevel::Critical;
    }

    if confidence >= 0.7 {
        return RiskLevel::High;
    }

    // Evaluar factores adicionales
    let mut risk_factors = 0;

    // Múltiples tipos de ataque
    if attack_types.len() > 2 {
        risk_factors += 1;
    }

    // Palabras clave peligrosas
    let dangerous_keywords = ["drop", "delete", "exec", "execute", "xp_cmdshell"];
    for keyword in &dangerous_keywords {
        if payload.sql_keywords.contains(&keyword.to_string()) {
            risk_factors += 2;
            break;
        }
    }

    // Múltiples técnicas de encoding
    if payload.encoding_detected.len() > 1 {
        risk_factors += 1;
    }

    // Ataques de tiempo
    if attack_types.contains(&SqlAttackType::Time) {
        risk_factors += 1;
    }

    match risk_factors {
        0..=1 if confidence >= 0.5 => RiskLevel::Medium,
        0..=1 => RiskLevel::Low,
        2..=3 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

/// Genera sugerencias de mitigación
fn generate_mitigation_suggestions(&self, attack_types: &[SqlAttackType], payload: &PayloadAnalysis) -> Vec<String> {
    let mut suggestions = Vec::new();

    // Sugerencias generales
    suggestions.push("Implementar prepared statements/parameterized queries".to_string());
    suggestions.push("Validar y sanitizar todas las entradas de usuario".to_string());
    suggestions.push("Aplicar principio de menor privilegio en base de datos".to_string());
    suggestions.push("Implementar Web Application Firewall (WAF)".to_string());

    // Sugerencias específicas por tipo de ataque
    for attack_type in attack_types {
        match attack_type {
            SqlAttackType::Union => {
                suggestions.push("Filtrar palabras clave UNION y SELECT en entradas".to_string());
                suggestions.push("Limitar resultado de queries a un solo conjunto".to_string());
            },
            SqlAttackType::Time => {
                suggestions.push("Implementar timeouts en queries de base de datos".to_string());
                suggestions.push("Monitorear tiempo de respuesta de queries".to_string());
            },
            SqlAttackType::Error => {
                suggestions.push("Suprimir mensajes de error detallados en producción".to_string());
                suggestions.push("Implementar logging centralizado de errores".to_string());
            },
            SqlAttackType::NoSql => {
                suggestions.push("Validar tipos de datos en queries NoSQL".to_string());
                suggestions.push("Evitar evaluación de JavaScript en MongoDB".to_string());
            },
            _ => {}
        }
    }

    // Sugerencias basadas en encoding detectado
    if !payload.encoding_detected.is_empty() {
        suggestions.push("Implementar decodificación y normalización de entradas".to_string());
        suggestions.push("Validar entradas después de decodificación completa".to_string());
    }

    suggestions
}

/// Obtiene estadísticas del detector
pub fn get_statistics(&self) -> HashMap<String, usize> {
    let mut stats = HashMap::new();

    stats.insert("total_patterns".to_string(), self.patterns.len());
    stats.insert("encoding_patterns".to_string(), self.encoding_patterns.len());
    stats.insert("bypass_patterns".to_string(), self.bypass_patterns.len());

    // Contar patrones por tipo
    let mut type_counts = HashMap::new();
    for pattern in &self.patterns {
        *type_counts.entry(format!("{:?}", pattern.attack_type)).or_insert(0) += 1;
    }

    for (attack_type, count) in type_counts {
        stats.insert(format!("patterns_{}", attack_type.to_lowercase()), count);
    }

    stats
}
}

impl Default for SqlInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Lazy static para regex patterns que se usan frecuentemente
static SQL_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(select|union|insert|update|delete|drop|create|alter|exec|execute)\b").unwrap()
});

/// Utilidades adicionales para análisis SQL
pub mod utils {
    use super::*;

    /// Verifica si un string contiene palabras clave SQL básicas
    pub fn contains_sql_keywords(input: &str) -> bool {
        SQL_KEYWORDS.is_match(input)
    }

    /// Extrae todas las palabras clave SQL de un string
    pub fn extract_sql_keywords(input: &str) -> Vec<String> {
        SQL_KEYWORDS.captures_iter(input)
            .map(|cap| cap[1].to_lowercase())
            .collect()
    }

    /// Calcula un hash del payload para tracking
    pub fn payload_hash(payload: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sql_injection_detection() {
        let detector = SqlInjectionDetector::new();

        let payload = "1' UNION SELECT * FROM users--";
        let result = detector.analyze(payload).unwrap();

        assert!(result.is_detected);
        assert!(result.confidence_score > 0.7);
        assert!(result.attack_types.contains(&SqlAttackType::Union));
    }

    #[test]
    fn test_time_based_injection() {
        let detector = SqlInjectionDetector::new();

        let payload = "1; WAITFOR DELAY '00:00:05'--";
        let result = detector.analyze(payload).unwrap();

        assert!(result.is_detected);
        assert!(result.attack_types.contains(&SqlAttackType::Time));
    }

    #[test]
    fn test_encoded_payload() {
        let detector = SqlInjectionDetector::new();

        let payload = "1%27%20UNION%20SELECT%20*%20FROM%20users--";
        let result = detector.analyze(payload).unwrap();

        assert!(result.is_detected);
        assert!(!result.payload_analysis.encoding_detected.is_empty());
    }

    #[test]
    fn test_nosql_injection() {
        let detector = SqlInjectionDetector::new();

        let payload = r#"{"username": {"$ne": null}, "password": {"$ne": null}}"#;
        let result = detector.analyze(payload).unwrap();

        assert!(result.is_detected);
        assert!(result.attack_types.contains(&SqlAttackType::NoSql));
    }

    #[test]
    fn test_false_positive_reduction() {
        let detector = SqlInjectionDetector::new();

        let legitimate_query = "SELECT name FROM products WHERE category = 'electronics'";
        let result = detector.analyze(legitimate_query).unwrap();

        // Este debería tener baja confianza ya que es una query legítima
        assert!(result.confidence_score < 0.5);
    }
}
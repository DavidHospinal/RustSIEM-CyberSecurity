use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

// Removed unused imports
use urlencoding;
use html_escape;
/// Detector especializado en Cross-Site Scripting (XSS)
#[derive(Clone)]
pub struct XssDetector {
    patterns: Vec<XssPattern>,
    encoding_patterns: Vec<Regex>,
    context_analyzers: HashMap<XssContext, Vec<Regex>>,
    filter_bypass_patterns: Vec<Regex>,
    confidence_weights: HashMap<String, f64>,
}

/// Representa un patrón de XSS con metadatos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssPattern {
    pub name: String,
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub confidence: f64,
    pub attack_type: XssAttackType,
    pub context: XssContext,
    pub description: String,
}

/// Tipos de ataques XSS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum XssAttackType {
    Reflected,
    Stored,
    Dom,
    Universal,
    MutationBased,
    PrototypePollution,
    CspBypass,
}

/// Contextos donde puede ocurrir XSS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum XssContext {
    HtmlContent,
    HtmlAttribute,
    JavascriptString,
    JavascriptCode,
    CssStyle,
    UrlParameter,
    HttpHeader,
    SvgContent,
    Unknown,
}

/// Resultado del análisis de XSS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssDetectionResult {
    pub is_detected: bool,
    pub confidence_score: f64,
    pub attack_types: Vec<XssAttackType>,
    pub contexts: Vec<XssContext>,
    pub matched_patterns: Vec<String>,
    pub payload_analysis: XssPayloadAnalysis,
    pub risk_level: RiskLevel,
    pub bypass_techniques: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

/// Análisis detallado del payload XSS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssPayloadAnalysis {
    pub decoded_payload: String,
    pub encoding_methods: Vec<String>,
    pub html_tags: Vec<String>,
    pub javascript_events: Vec<String>,
    pub javascript_functions: Vec<String>,
    pub css_properties: Vec<String>,
    pub url_schemes: Vec<String>,
    pub special_chars: Vec<char>,
    pub obfuscation_techniques: Vec<String>,
}

/// Nivel de riesgo del ataque XSS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl XssDetector {
    pub fn new() -> Self {
        let patterns = Self::initialize_patterns();
        let encoding_patterns = Self::initialize_encoding_patterns();
        let context_analyzers = Self::initialize_context_analyzers();
        let filter_bypass_patterns = Self::initialize_filter_bypass_patterns();
        let confidence_weights = Self::initialize_confidence_weights();

        Self {
            patterns,
            encoding_patterns,
            context_analyzers,
            filter_bypass_patterns,
            confidence_weights,
        }
    }

    /// Analiza un input para detectar XSS
    pub fn analyze(&self, input: &str) -> Result<XssDetectionResult> {
        let decoded_input = self.decode_input(input)?;
        let normalized_input = self.normalize_input(&decoded_input);

        let mut matched_patterns = Vec::new();
        let mut attack_types = Vec::new();
        let mut contexts = Vec::new();
        let mut total_confidence = 0.0;
        let mut pattern_count = 0;

        // Analizar contra todos los patrones
        for pattern in &self.patterns {
            if pattern.regex.is_match(&normalized_input) {
                matched_patterns.push(pattern.name.clone());

                if !attack_types.contains(&pattern.attack_type) {
                    attack_types.push(pattern.attack_type.clone());
                }

                if !contexts.contains(&pattern.context) {
                    contexts.push(pattern.context.clone());
                }

                total_confidence += pattern.confidence;
                pattern_count += 1;
            }
        }

        // Análisis de bypass techniques
        let bypass_techniques = self.analyze_bypass_techniques(&normalized_input);
        let bypass_confidence = bypass_techniques.len() as f64 * 0.1;
        total_confidence += bypass_confidence;

        // Análisis contextual adicional
        let context_confidence = self.analyze_contexts(&normalized_input, &mut contexts);
        total_confidence += context_confidence;

        // Calcular confidence score final
        let confidence_score = if pattern_count > 0 {
            (total_confidence / (pattern_count as f64 + 1.0)).min(1.0)
        } else {
            0.0
        };

        // Determinar si hay detección
        let is_detected = confidence_score >= 0.25;

        // Análisis del payload
        let payload_analysis = self.analyze_payload(input, &decoded_input);

        // Determinar nivel de riesgo
        let risk_level = self.determine_risk_level(confidence_score, &attack_types, &payload_analysis);

        // Generar sugerencias de mitigación
        let mitigation_suggestions = self.generate_mitigation_suggestions(&attack_types, &contexts, &payload_analysis);

        Ok(XssDetectionResult {
            is_detected,
            confidence_score,
            attack_types,
            contexts,
            matched_patterns,
            payload_analysis,
            risk_level,
            bypass_techniques,
            mitigation_suggestions,
        })
    }

    /// Inicializa los patrones de detección XSS
    fn initialize_patterns() -> Vec<XssPattern> {
        let mut patterns = Vec::new();

        // Script tags básicos
        patterns.push(XssPattern {
            name: "script_tag".to_string(),
            regex: Regex::new(r"(?i)<\s*script[^>]*>").unwrap(),
            confidence: 0.9,
            attack_type: XssAttackType::Reflected,
            context: XssContext::HtmlContent,
            description: "Script tag detected".to_string(),
        });

        patterns.push(XssPattern {
            name: "script_tag_with_src".to_string(),
            regex: Regex::new(r"(?i)<\s*script[^>]*src\s*=").unwrap(),
            confidence: 0.95,
            attack_type: XssAttackType::Reflected,
            context: XssContext::HtmlContent,
            description: "Script tag with external source".to_string(),
        });

        // Event handlers
        patterns.push(XssPattern {
            name: "javascript_events".to_string(),
            regex: Regex::new(r"(?i)\bon(load|error|click|focus|blur|change|submit|mouseover|mouseout|keydown|keyup|resize)\s*=").unwrap(),
            confidence: 0.85,
            attack_type: XssAttackType::Reflected,
            context: XssContext::HtmlAttribute,
            description: "JavaScript event handler".to_string(),
        });

        patterns.push(XssPattern {
            name: "advanced_events".to_string(),
            regex: Regex::new(r"(?i)\bon(animationend|animationstart|transitionend|beforeunload|hashchange|popstate|storage)\s*=").unwrap(),
            confidence: 0.8,
            attack_type: XssAttackType::Dom,
            context: XssContext::HtmlAttribute,
            description: "Advanced JavaScript event".to_string(),
        });

        // JavaScript schemes
        patterns.push(XssPattern {
            name: "javascript_scheme".to_string(),
            regex: Regex::new(r"(?i)javascript\s*:").unwrap(),
            confidence: 0.9,
            attack_type: XssAttackType::Reflected,
            context: XssContext::UrlParameter,
            description: "JavaScript URL scheme".to_string(),
        });

        patterns.push(XssPattern {
            name: "data_scheme_html".to_string(),
            regex: Regex::new(r"(?i)data\s*:\s*text/html").unwrap(),
            confidence: 0.85,
            attack_type: XssAttackType::Reflected,
            context: XssContext::UrlParameter,
            description: "Data URL with HTML content".to_string(),
        });

        // Expression and eval
        patterns.push(XssPattern {
            name: "javascript_eval".to_string(),
            regex: Regex::new(r"(?i)\b(eval|function|settimeout|setinterval)\s*\(").unwrap(),
            confidence: 0.8,
            attack_type: XssAttackType::Dom,
            context: XssContext::JavascriptCode,
            description: "JavaScript evaluation function".to_string(),
        });

        patterns.push(XssPattern {
            name: "css_expression".to_string(),
            regex: Regex::new(r"(?i)expression\s*\(").unwrap(),
            confidence: 0.9,
            attack_type: XssAttackType::Reflected,
            context: XssContext::CssStyle,
            description: "CSS expression (IE)".to_string(),
        });

        // SVG-based XSS
        patterns.push(XssPattern {
            name: "svg_script".to_string(),
            regex: Regex::new(r"(?i)<\s*svg[^>]*>.*?<\s*script").unwrap(),
            confidence: 0.9,
            attack_type: XssAttackType::Reflected,
            context: XssContext::SvgContent,
            description: "SVG with embedded script".to_string(),
        });

        patterns.push(XssPattern {
            name: "svg_onload".to_string(),
            regex: Regex::new(r"(?i)<\s*svg[^>]*onload\s*=").unwrap(),
            confidence: 0.85,
            attack_type: XssAttackType::Reflected,
            context: XssContext::SvgContent,
            description: "SVG onload event".to_string(),
        });

        // DOM manipulation
        patterns.push(XssPattern {
            name: "dom_manipulation".to_string(),
            regex: Regex::new(r"(?i)\b(document\.(write|writeln|createElement|innerHTML|outerHTML)|window\.(open|location|name))\s*[\(\[]").unwrap(),
            confidence: 0.8,
            attack_type: XssAttackType::Dom,
            context: XssContext::JavascriptCode,
            description: "DOM manipulation function".to_string(),
        });

        // Template literals and modern JS
        patterns.push(XssPattern {
            name: "template_literals".to_string(),
            regex: Regex::new(r"`[^`]*\$\{[^}]+\}[^`]*`").unwrap(),
            confidence: 0.7,
            attack_type: XssAttackType::Dom,
            context: XssContext::JavascriptString,
            description: "JavaScript template literal".to_string(),
        });

        // Prototype pollution
        patterns.push(XssPattern {
            name: "prototype_pollution".to_string(),
            regex: Regex::new(r"(?i)(__proto__|constructor\.prototype|Object\.prototype)").unwrap(),
            confidence: 0.85,
            attack_type: XssAttackType::PrototypePollution,
            context: XssContext::JavascriptCode,
            description: "Prototype pollution attempt".to_string(),
        });

        // Import/dynamic import
        patterns.push(XssPattern {
            name: "dynamic_import".to_string(),
            regex: Regex::new(r"(?i)\b(import|importScripts)\s*\(").unwrap(),
            confidence: 0.8,
            attack_type: XssAttackType::Dom,
            context: XssContext::JavascriptCode,
            description: "Dynamic import statement".to_string(),
        });

        // CSS-based XSS
        patterns.push(XssPattern {
            name: "css_import".to_string(),
            regex: Regex::new(r"(?i)@import\s+url\s*\(").unwrap(),
            confidence: 0.7,
            attack_type: XssAttackType::Reflected,
            context: XssContext::CssStyle,
            description: "CSS import with URL".to_string(),
        });

        patterns.push(XssPattern {
            name: "css_background_image".to_string(),
            regex: Regex::new(r"(?i)background.*url.*javascript:").unwrap(),
            confidence: 0.85,
            attack_type: XssAttackType::Reflected,
            context: XssContext::CssStyle,
            description: "CSS background with JavaScript URL".to_string(),
        });

        // Meta refresh and other tags
        patterns.push(XssPattern {
            name: "meta_refresh".to_string(),
            regex: Regex::new(r"(?i)<\s*meta[^>]*refresh[^>]*url").unwrap(),
            confidence: 0.8,
            attack_type: XssAttackType::Reflected,
            context: XssContext::HtmlContent,
            description: "Meta refresh with URL".to_string(),
        });

        patterns.push(XssPattern {
            name: "iframe_srcdoc".to_string(),
            regex: Regex::new(r"(?i)<\s*iframe[^>]*srcdoc\s*=").unwrap(),
            confidence: 0.85,
            attack_type: XssAttackType::Reflected,
            context: XssContext::HtmlContent,
            description: "Iframe with srcdoc attribute".to_string(),
        });

        patterns
    }

    /// Inicializa patrones de codificación
    fn initialize_encoding_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"%[0-9a-fA-F]{2}").unwrap(),                    // URL encoding
            Regex::new(r"&#x?[0-9a-fA-F]+;").unwrap(),                 // HTML entities
            Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap(),                 // Hex escape
            Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap(),                 // Unicode escape
            Regex::new(r"\\[0-7]{1,3}").unwrap(),                      // Octal escape
            Regex::new(r"String\.fromCharCode\s*\(").unwrap(),         // JavaScript fromCharCode
            Regex::new(r"unescape\s*\(").unwrap(),                     // JavaScript unescape
            Regex::new(r"decodeURI(?:Component)?\s*\(").unwrap(),      // JavaScript decode functions
        ]
    }

    /// Inicializa analizadores por contexto
    fn initialize_context_analyzers() -> HashMap<XssContext, Vec<Regex>> {
        let mut analyzers = HashMap::new();
        
        // HTML Content context
        analyzers.insert(XssContext::HtmlContent, vec![
            Regex::new(r"(?i)<\s*[a-z]+[^>]*>").unwrap(),              // HTML tags
            Regex::new(r"(?i)<!--.*?-->").unwrap(),                    // HTML comments
        ]);
        
        // HTML Attribute context
        analyzers.insert(XssContext::HtmlAttribute, vec![
            Regex::new(r"(?i)\w+\s*=").unwrap(),   // Attribute assignments
            Regex::new(r"(?i)style\s*=").unwrap(),                     // Style attributes
        ]);
        
        // JavaScript contexts
        analyzers.insert(XssContext::JavascriptCode, vec![
            Regex::new(r"(?i)\b(var|let|const|function|class|if|for|while|try|catch)\b").unwrap(),
            Regex::new(r"[{};()]").unwrap(),                           // JS syntax chars
        ]);
        
        // CSS context
        analyzers.insert(XssContext::CssStyle, vec![
            Regex::new(r"(?i)[a-z-]+\s*:\s*[^;]+;?").unwrap(),         // CSS properties
            Regex::new(r"(?i)@(import|media|keyframes)").unwrap(),     // CSS at-rules
        ]);
        
        analyzers
    }

    /// Inicializa patrones de bypass de filtros
    fn initialize_filter_bypass_patterns() -> Vec<Regex> {
        vec![
            // Espacios y caracteres especiales
            Regex::new(r"(?i)<\s+script").unwrap(),
            Regex::new(r"(?i)<script\s*/\s*>").unwrap(),
            Regex::new(r"(?i)<script\s+[^>]*>").unwrap(),
            
            // Comentarios HTML
            Regex::new(r"(?i)<script<!--").unwrap(),
            Regex::new(r"(?i)<!--.*?script").unwrap(),
            
            // Encoding mixto
            Regex::new(r"(?i)%3[cC]script").unwrap(),
            Regex::new(r"(?i)&lt;script").unwrap(),
            
            // Case variations
            Regex::new(r"(?i)sCrIpT").unwrap(),
            Regex::new(r"(?i)[sS][cC][rR][iI][pP][tT]").unwrap(),
            
            // Null bytes y caracteres especiales
            Regex::new(r"<script\x00").unwrap(),
            Regex::new(r"<script\r\n").unwrap(),
            
            // Event handler bypasses
            Regex::new(r"(?i)on\w+.*alert").unwrap(),
            Regex::new(r"(?i)javascript\s*:\s*/\*.*?\*/").unwrap(),
        ]
    }

    /// Inicializa pesos de confianza
    fn initialize_confidence_weights() -> HashMap<String, f64> {
        let mut weights = HashMap::new();
        weights.insert("multiple_contexts".to_string(), 0.15);
        weights.insert("encoding_detected".to_string(), 0.1);
        weights.insert("bypass_technique".to_string(), 0.2);
        weights.insert("dangerous_functions".to_string(), 0.25);
        weights.insert("obfuscation".to_string(), 0.15);
        weights
    }

    /// Decodifica el input usando múltiples métodos
    fn decode_input(&self, input: &str) -> Result<String> {
        let mut decoded = input.to_string();

        // URL decoding (múltiples pasadas para double encoding)
        for _ in 0..3 {
            if let Ok(url_decoded) = urlencoding::decode(&decoded) {
                let new_decoded = url_decoded.into_owned();
                if new_decoded == decoded {
                    break; // No more changes
                }
                decoded = new_decoded;
            }
        }

        // HTML entity decoding
        decoded = html_escape::decode_html_entities(&decoded).into_owned();

        // Hex decoding
        if decoded.contains("\\x") {
            let hex_regex = Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap();
            for cap in hex_regex.captures_iter(&decoded.clone()) {
                if let Ok(byte_val) = u8::from_str_radix(&cap[1], 16) {
                    let char_val = char::from(byte_val);
                    decoded = decoded.replace(&cap[0], &char_val.to_string());
                }
            }
        }

        // Unicode decoding
        if decoded.contains("\\u") {
            let unicode_regex = Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap();
            for cap in unicode_regex.captures_iter(&decoded.clone()) {
                if let Ok(code_point) = u32::from_str_radix(&cap[1], 16) {
                    if let Some(unicode_char) = char::from_u32(code_point) {
                        decoded = decoded.replace(&cap[0], &unicode_char.to_string());
                    }
                }
            }
        }

        // JavaScript string decoding
        if decoded.contains("String.fromCharCode") {
            let fromcharcode_regex = Regex::new(r"String\.fromCharCode\s*\(\s*([0-9,\s]+)\s*\)").unwrap();
            for cap in fromcharcode_regex.captures_iter(&decoded.clone()) {
                let char_codes: Vec<&str> = cap[1].split(',').collect();
                let mut decoded_string = String::new();
                
                for code_str in char_codes {
                    if let Ok(code) = code_str.trim().parse::<u32>() {
                        if let Some(ch) = char::from_u32(code) {
                            decoded_string.push(ch);
                        }
                    }
                }
                
                decoded = decoded.replace(&cap[0], &decoded_string);
            }
        }

        Ok(decoded)
    }

    /// Normaliza el input para mejor detección
    fn normalize_input(&self, input: &str) -> String {
        let mut normalized = input.to_lowercase();
        
        // Remover espacios múltiples pero preservar estructura
        normalized = Regex::new(r"\s+").unwrap().replace_all(&normalized, " ").to_string();
        
        // Remover comentarios HTML pero mantener estructura
        normalized = Regex::new(r"<!--.*?-->").unwrap().replace_all(&normalized, "").to_string();
        
        // Normalizar quotes
        normalized = normalized.replace("&#39;", "'").replace("&#34;", "\"").replace("&quot;", "\"");

        normalized
    }

    /// Analiza técnicas de bypass
    fn analyze_bypass_techniques(&self, input: &str) -> Vec<String> {
        let mut techniques = Vec::new();

        for (i, pattern) in self.filter_bypass_patterns.iter().enumerate() {
            if pattern.is_match(input) {
                let technique = match i {
                    0..=2 => "whitespace_variation",
                    3..=4 => "html_comment_bypass",
                    5..=6 => "encoding_bypass",
                    7..=8 => "case_variation",
                    9..=10 => "null_byte_injection",
                    11..=12 => "event_handler_bypass",
                    _ => "unknown_bypass",
                };
                techniques.push(technique.to_string());
            }
        }

        techniques
    }

    /// Analiza contextos específicos
    fn analyze_contexts(&self, input: &str, contexts: &mut Vec<XssContext>) -> f64 {
        let mut context_confidence = 0.0;

        for (context, analyzers) in &self.context_analyzers {
            for analyzer in analyzers {
                if analyzer.is_match(input) {
                    if !contexts.contains(context) {
                        contexts.push(context.clone());
                        context_confidence += 0.1;
                    }
                }
            }
        }

        context_confidence
    }

    /// Analiza el payload en detalle
    fn analyze_payload(&self, original: &str, decoded: &str) -> XssPayloadAnalysis {
        let mut encoding_methods = Vec::new();
        let mut html_tags = Vec::new();
        let mut javascript_events = Vec::new();
        let mut javascript_functions = Vec::new();
        let mut css_properties = Vec::new();
        let mut url_schemes = Vec::new();
        let mut special_chars = Vec::new();
        let mut obfuscation_techniques = Vec::new();

        // Detectar métodos de encoding
        for (i, pattern) in self.encoding_patterns.iter().enumerate() {
            if pattern.is_match(original) {
                encoding_methods.push(match i {
                    0 => "url_encoding".to_string(),
                    1 => "html_entities".to_string(),
                    2 => "hex_escape".to_string(),
                    3 => "unicode_escape".to_string(),
                    4 => "octal_escape".to_string(),
                    5 => "fromcharcode".to_string(),
                    6 => "unescape".to_string(),
                    7 => "decode_functions".to_string(),
                    _ => "unknown".to_string(),
                });
            }
        }

        // Extraer HTML tags
        let html_tag_regex = Regex::new(r"(?i)<\s*([a-z]+)").unwrap();
        for cap in html_tag_regex.captures_iter(decoded) {
            let tag = cap[1].to_lowercase();
            if !html_tags.contains(&tag) {
                html_tags.push(tag);
            }
        }

        // Extraer JavaScript events
        let js_event_regex = Regex::new(r"(?i)\bon([a-z]+)\s*=").unwrap();
        for cap in js_event_regex.captures_iter(decoded) {
            let event = format!("on{}", cap[1].to_lowercase());
            if !javascript_events.contains(&event) {
                javascript_events.push(event);
            }
        }

        // Extraer JavaScript functions
        let js_func_regex = Regex::new(r"(?i)\b(alert|confirm|prompt|eval|function|settimeout|setinterval|document\.write|console\.log|window\.open)\s*\(").unwrap();
        for cap in js_func_regex.captures_iter(decoded) {
            let func = cap[1].to_lowercase();
            if !javascript_functions.contains(&func) {
                javascript_functions.push(func);
            }
        }

        // Extraer CSS properties
        let css_prop_regex = Regex::new(r"(?i)\b([a-z-]+)\s*:\s*[^;]+").unwrap();
        for cap in css_prop_regex.captures_iter(decoded) {
            let prop = cap[1].to_lowercase();
            if !css_properties.contains(&prop) {
                css_properties.push(prop);
            }
        }

        // Extraer URL schemes
        let url_scheme_regex = Regex::new(r"(?i)\b([a-z]+)://").unwrap();
        for cap in url_scheme_regex.captures_iter(decoded) {
            let scheme = cap[1].to_lowercase();
            if !url_schemes.contains(&scheme) {
                url_schemes.push(scheme);
            }
        }

        // JavaScript schemes
        if decoded.to_lowercase().contains("javascript:") {
            url_schemes.push("javascript".to_string());
        }
        if decoded.to_lowercase().contains("data:") {
            url_schemes.push("data".to_string());
        }

        // Detectar caracteres especiales
        for ch in decoded.chars() {
            match ch {
                '<' | '>' | '"' | '\'' | '&' | ';' | '(' | ')' | '{' | '}' |
                '[' | ']' | '=' | '+' | '*' | '/' | '\\' | '|' | '%' | '#' |
                '`' | '~' | '^' | '$' | '!' | '?' => {
                    if !special_chars.contains(&ch) {
                        special_chars.push(ch);
                    }
                },
                _ => {}
            }
        }

        // Detectar técnicas de obfuscación
        if decoded.contains("String.fromCharCode") {
            obfuscation_techniques.push("fromcharcode".to_string());
        }
        if decoded.contains("eval(") {
            obfuscation_techniques.push("eval".to_string());
        }
        if Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap().is_match(original) {
            obfuscation_techniques.push("hex_encoding".to_string());
        }
        if Regex::new(r"&#x?[0-9]+;").unwrap().is_match(original) {
            obfuscation_techniques.push("html_entities".to_string());
        }
        if decoded.contains("/*") && decoded.contains("*/") {
            obfuscation_techniques.push("comment_hiding".to_string());
        }

        XssPayloadAnalysis {
            decoded_payload: decoded.to_string(),
            encoding_methods,
            html_tags,
            javascript_events,
            javascript_functions,
            css_properties,
            url_schemes,
            special_chars,
            obfuscation_techniques,
        }
    }

    /// Determina el nivel de riesgo
    fn determine_risk_level(&self, confidence: f64, attack_types: &[XssAttackType], payload: &XssPayloadAnalysis) -> RiskLevel {
            if confidence >= 0.9 {
                return RiskLevel::Critical;
            }

            if confidence >= 0.7 {
                return RiskLevel::High;
            }

            let mut risk_factors = 0;

            // Funciones JavaScript peligrosas
            let dangerous_functions = ["eval", "function", "settimeout", "document.write"];
            for func in &dangerous_functions {
                if payload.javascript_functions.contains(&func.to_string()) {
                    risk_factors += 2;
                    break;
                }
            }

            // Múltiples técnicas de encoding
            if payload.encoding_methods.len() > 1 {
                risk_factors += 1;
            }

            // Ataques DOM o prototype pollution
            if attack_types.contains(&XssAttackType::Dom) ||
                attack_types.contains(&XssAttackType::PrototypePollution) {
                risk_factors += 1;
            }

            // Tags peligrosos
            let dangerous_tags = ["script", "iframe", "object", "embed"];
            for tag in &dangerous_tags {
                if payload.html_tags.contains(&tag.to_string()) {
                    risk_factors += 1;
                    break;
                }
            }

            // URL schemes externos
            if payload.url_schemes.iter().any(|s| s == "http" || s == "https" || s == "ftp") {
                risk_factors += 1;
            }

            match risk_factors {
                0..=1 if confidence >= 0.4 => RiskLevel::Medium,
                0..=1 => RiskLevel::Low,
                2..=3 => RiskLevel::High,
                _ => RiskLevel::Critical,
            }
        }

    /// Genera sugerencias de mitigación
    fn generate_mitigation_suggestions(&self, attack_types: &[XssAttackType], contexts: &[XssContext], payload: &XssPayloadAnalysis) -> Vec<String> {
            let mut suggestions = Vec::new();

            // Sugerencias generales
            suggestions.push("Implementar Content Security Policy (CSP) restrictivo".to_string());
            suggestions.push("Escapar todos los datos de salida según el contexto".to_string());
            suggestions.push("Validar y sanitizar todas las entradas de usuario".to_string());
            suggestions.push("Usar frameworks que escapen automáticamente (React, Angular)".to_string());
            suggestions.push("Implementar HTTP security headers (X-XSS-Protection, X-Content-Type-Options)".to_string());

            // Sugerencias específicas por tipo de ataque
            for attack_type in attack_types {
                match attack_type {
                    XssAttackType::Reflected => {
                        suggestions.push("Validar parámetros URL y formularios en servidor".to_string());
                        suggestions.push("Usar encoding contextual para datos reflejados".to_string());
                    },
                    XssAttackType::Stored => {
                        suggestions.push("Sanitizar datos antes de almacenar en base de datos".to_string());
                        suggestions.push("Implementar validación de entrada estricta".to_string());
                        suggestions.push("Usar whitelist de tags HTML permitidos".to_string());
                    },
                    XssAttackType::Dom => {
                        suggestions.push("Evitar uso de innerHTML, usar textContent o innerText".to_string());
                        suggestions.push("Validar datos antes de manipulación DOM".to_string());
                        suggestions.push("Usar bibliotecas de templating seguras".to_string());
                    },
                    XssAttackType::PrototypePollution => {
                        suggestions.push("Usar Object.create(null) para objetos sin prototipo".to_string());
                        suggestions.push("Validar claves de objeto antes de asignación".to_string());
                        suggestions.push("Implementar controles de integridad de prototipos".to_string());
                    },
                    XssAttackType::CspBypass => {
                        suggestions.push("Revisar y fortalecer política CSP actual".to_string());
                        suggestions.push("Evitar 'unsafe-inline' y 'unsafe-eval' en CSP".to_string());
                        suggestions.push("Usar nonces o hashes para scripts inline".to_string());
                    },
                    _ => {}
                }
            }

            // Sugerencias específicas por contexto
            for context in contexts {
                match context {
                    XssContext::HtmlContent => {
                        suggestions.push("Usar HTML encoding para contenido dinámico".to_string());
                        suggestions.push("Implementar whitelist de tags HTML permitidos".to_string());
                    },
                    XssContext::HtmlAttribute => {
                        suggestions.push("Usar attribute encoding para valores de atributos".to_string());
                        suggestions.push("Validar nombres de atributos contra whitelist".to_string());
                    },
                    XssContext::JavascriptString => {
                        suggestions.push("Usar JavaScript string encoding".to_string());
                        suggestions.push("Evitar concatenación directa en strings JS".to_string());
                    },
                    XssContext::JavascriptCode => {
                        suggestions.push("Nunca concatenar datos de usuario en código JavaScript".to_string());
                        suggestions.push("Usar JSON.stringify para datos estructurados".to_string());
                    },
                    XssContext::CssStyle => {
                        suggestions.push("Usar CSS encoding para valores de propiedades".to_string());
                        suggestions.push("Whitelist de propiedades CSS permitidas".to_string());
                    },
                    XssContext::UrlParameter => {
                        suggestions.push("Usar URL encoding para parámetros dinámicos".to_string());
                        suggestions.push("Validar esquemas de URL permitidos".to_string());
                    },
                    XssContext::SvgContent => {
                        suggestions.push("Sanitizar contenido SVG estrictamente".to_string());
                        suggestions.push("Remover elementos script de SVG uploads".to_string());
                    },
                    _ => {}
                }
            }

            // Sugerencias basadas en análisis del payload
            if !payload.encoding_methods.is_empty() {
                suggestions.push("Implementar decodificación recursiva en validación".to_string());
                suggestions.push("Normalizar entradas antes de validación".to_string());
            }

            if !payload.javascript_functions.is_empty() {
                suggestions.push("Implementar CSP para bloquear JavaScript inline".to_string());
                suggestions.push("Usar Trusted Types API para prevenir inyección DOM".to_string());
            }

            if !payload.obfuscation_techniques.is_empty() {
                suggestions.push("Implementar detección de obfuscación en WAF".to_string());
                suggestions.push("Monitorear patrones de encoding múltiple".to_string());
            }

            suggestions.sort();
            suggestions.dedup();
            suggestions
        }

    /// Obtiene estadísticas del detector
    pub fn get_statistics(&self) -> HashMap<String, usize> {
            let mut stats = HashMap::new();

            stats.insert("total_patterns".to_string(), self.patterns.len());
            stats.insert("encoding_patterns".to_string(), self.encoding_patterns.len());
            stats.insert("bypass_patterns".to_string(), self.filter_bypass_patterns.len());

            // Contar patrones por tipo de ataque
            let mut attack_type_counts = HashMap::new();
            for pattern in &self.patterns {
                *attack_type_counts.entry(format!("{:?}", pattern.attack_type)).or_insert(0) += 1;
            }

            for (attack_type, count) in attack_type_counts {
                stats.insert(format!("patterns_{}", attack_type.to_lowercase()), count);
            }

            // Contar patrones por contexto
            let mut context_counts = HashMap::new();
            for pattern in &self.patterns {
                *context_counts.entry(format!("{:?}", pattern.context)).or_insert(0) += 1;
            }

            for (context, count) in context_counts {
                stats.insert(format!("context_{}", context.to_lowercase()), count);
            }

            stats
        }

    // Verifica si un payload específico es un bypass conocido
    pub fn check_known_bypass(&self, payload: &str) -> Option<String> {
            let known_bypasses = [
                (r"(?i)<svg/onload=alert\(1\)>", "svg_onload_bypass"),
                (r"(?i)<img src=x onerror=alert\(1\)>", "img_onerror_bypass"),
                (r"(?i)javascript:alert\(1\)", "javascript_scheme_bypass"),
                (r"(?i)<script>alert\(1\)</script>", "basic_script_injection"),
                (r"(?i)'><script>alert\(1\)</script>", "attribute_escape_bypass"),
                (r"(?i)</script><script>alert\(1\)</script>", "script_context_escape"),
                (r"(?i)onmouseover=alert\(1\)", "event_handler_bypass"),
                (r"(?i)eval.*atob", "base64_eval_bypass"),
       ];

       for (pattern, name) in &known_bypasses {
           if let Ok(regex) = Regex::new(pattern) {
               if regex.is_match(payload) {
                   return Some(name.to_string());
               }
           }
       }

       None
   }
}

impl Default for XssDetector {
   fn default() -> Self {
       Self::new()
   }
}

/// Lazy static para regex patterns comúnmente usados
static XSS_BASIC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
   vec![
       Regex::new(r"(?i)<script[^>]*>").unwrap(),
       Regex::new(r"(?i)javascript\s*:").unwrap(),
       Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
       Regex::new(r"(?i)<\s*svg[^>]*onload").unwrap(),
   ]
});

/// Utilidades adicionales para análisis XSS
pub mod utils {
   use super::*;

   /// Verifica rápidamente si un string contiene patrones XSS básicos
   pub fn quick_xss_check(input: &str) -> bool {
       XSS_BASIC_PATTERNS.iter().any(|pattern| pattern.is_match(input))
   }

   /// Extrae todos los tags HTML de un string
   pub fn extract_html_tags(input: &str) -> Vec<String> {
       let tag_regex = Regex::new(r"(?i)<\s*([a-z]+)").unwrap();
       tag_regex.captures_iter(input)
           .map(|cap| cap[1].to_lowercase())
           .collect()
   }

   /// Extrae todos los event handlers de un string
   pub fn extract_event_handlers(input: &str) -> Vec<String> {
       let event_regex = Regex::new(r"(?i)\bon([a-z]+)\s*=").unwrap();
       event_regex.captures_iter(input)
           .map(|cap| format!("on{}", cap[1].to_lowercase()))
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

   /// Normaliza un payload XSS para comparación
   pub fn normalize_xss_payload(payload: &str) -> String {
       let mut normalized = payload.to_lowercase();
       normalized = Regex::new(r"\s+").unwrap().replace_all(&normalized, " ").to_string();
       normalized = Regex::new(r"<!--.*?-->").unwrap().replace_all(&normalized, "").to_string();
       normalized.trim().to_string()
   }

   /// Detecta el contexto más probable para un payload
   pub fn detect_likely_context(payload: &str) -> XssContext {
       if payload.contains('<') && payload.contains('>') {
           return XssContext::HtmlContent;
       }
       if payload.contains("on") && payload.contains("=") {
           return XssContext::HtmlAttribute;
       }
       if payload.contains("javascript:") {
           return XssContext::UrlParameter;
       }
       if payload.contains("function") || payload.contains("var ") {
           return XssContext::JavascriptCode;
       }
       if payload.contains(":") && (payload.contains("px") || payload.contains("color")) {
           return XssContext::CssStyle;
       }

       XssContext::Unknown
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn test_basic_script_tag() {
       let detector = XssDetector::new();

       let payload = "<script>alert('xss')</script>";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.confidence_score > 0.8);
       assert!(result.attack_types.contains(&XssAttackType::Reflected));
   }

   #[test]
   fn test_event_handler_xss() {
       let detector = XssDetector::new();

       let payload = "<img src=x onerror=alert(1)>";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.contexts.contains(&XssContext::HtmlAttribute));
   }

   #[test]
   fn test_javascript_scheme() {
       let detector = XssDetector::new();

       let payload = "javascript:alert(document.cookie)";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.contexts.contains(&XssContext::UrlParameter));
   }

   #[test]
   fn test_svg_xss() {
       let detector = XssDetector::new();

       let payload = "<svg onload=alert(1)>";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.contexts.contains(&XssContext::SvgContent));
   }

   #[test]
   fn test_encoded_xss() {
       let detector = XssDetector::new();

       let payload = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(!result.payload_analysis.encoding_methods.is_empty());
   }

   #[test]
   fn test_dom_xss() {
       let detector = XssDetector::new();

       let payload = "document.write('<script>alert(1)</script>')";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.attack_types.contains(&XssAttackType::Dom));
   }

   #[test]
   fn test_prototype_pollution() {
       let detector = XssDetector::new();

       let payload = "__proto__.polluted = true";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.attack_types.contains(&XssAttackType::PrototypePollution));
   }

   #[test]
   fn test_false_positive_reduction() {
       let detector = XssDetector::new();

       let legitimate_html = "<p>Welcome to our website!</p>";
       let result = detector.analyze(legitimate_html).unwrap();

       // Este debería tener baja confianza ya que es HTML legítimo
       assert!(result.confidence_score < 0.3);
   }

   #[test]
   fn test_bypass_detection() {
       let detector = XssDetector::new();

       let payload = "<ScRiPt>alert(1)</ScRiPt>";
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(!result.bypass_techniques.is_empty());
   }

   #[test]
   fn test_multiple_encoding() {
       let detector = XssDetector::new();

       let payload = "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"; // Double URL encoded
       let result = detector.analyze(payload).unwrap();

       assert!(result.is_detected);
       assert!(result.payload_analysis.encoding_methods.contains(&"url_encoding".to_string()));
   }
}
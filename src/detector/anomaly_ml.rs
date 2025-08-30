use anyhow::{Result, Context};
use smartcore::linalg::basic::matrix::DenseMatrix;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use chrono::{DateTime, Utc, Duration, Timelike, Datelike};
use std::sync::{Arc, RwLock};

/// Detector de anomalías basado en Machine Learning
pub struct AnomalyMLDetector {
    models: Arc<RwLock<MLModels>>,
    feature_extractors: Vec<Box<dyn FeatureExtractor + Send + Sync>>,
    training_data: Arc<RwLock<TrainingDataBuffer>>,
    config: AnomalyMLConfig,
    statistics: Arc<RwLock<MLStatistics>>,
}

// Implementación manual de Clone después de la definición:
impl Clone for AnomalyMLDetector {
    fn clone(&self) -> Self {
        Self {
            models: Arc::clone(&self.models),
            feature_extractors: Vec::new(), // Se inicializa vacío
            training_data: Arc::clone(&self.training_data),
            config: self.config.clone(),
            statistics: Arc::clone(&self.statistics),
        }
    }
}

/// Configuración del detector ML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyMLConfig {
    pub training_window_hours: u32,
    pub min_training_samples: usize,
    pub retrain_interval_hours: u32,
    pub anomaly_threshold: f64,
    pub isolation_forest_contamination: f64,
    pub kmeans_clusters: usize,
    pub feature_scaling: bool,
    pub online_learning: bool,
    pub ensemble_voting: bool,
}

/// Modelos de ML entrenados
#[derive(Debug)]
pub struct MLModels {
    pub false_positive_classifier: Option<FalsePositiveModel>,
    pub anomaly_detector: Option<BasicAnomalyDetector>,
    pub similarity_matcher: Option<SimilarityMatcher>,
    pub last_training: Option<DateTime<Utc>>,
    pub model_performance: ModelPerformance,
}

/// Modelo básico para clasificación de falsos positivos
#[derive(Debug, Clone)]
pub struct FalsePositiveModel {
    pub feature_thresholds: HashMap<String, f64>,
    pub whitelist_patterns: Vec<WhitelistPattern>,
    pub confidence_threshold: f64,
    pub training_data_size: usize,
}

/// Detector de anomalías básico usando clustering
#[derive(Debug, Clone)]
pub struct BasicAnomalyDetector {
    pub cluster_centers: Vec<Vec<f64>>,
    pub distance_threshold: f64,
    pub normal_behavior_baseline: Vec<f64>,
}

/// Matcher de similitud para eventos
#[derive(Debug, Clone)]
pub struct SimilarityMatcher {
    pub known_false_positives: Vec<EventSignature>,
    pub similarity_threshold: f64,
}

/// Patrón en whitelist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistPattern {
    pub pattern_type: String,
    pub pattern_value: String,
    pub confidence: f64,
    pub created_at: DateTime<Utc>,
    pub times_matched: u32,
}

/// Firma de evento para comparación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSignature {
    pub features_hash: String,
    pub source_pattern: String,
    pub event_type_pattern: String,
    pub payload_fingerprint: String,
    pub marked_fp_count: u32,
    pub last_seen: DateTime<Utc>,
}

/// Buffer de datos de entrenamiento
#[derive(Debug)]
pub struct TrainingDataBuffer {
    pub samples: VecDeque<TrainingSample>,
    pub max_size: usize,
    pub last_cleanup: DateTime<Utc>,
}

/// Muestra de entrenamiento
#[derive(Debug, Clone)]
pub struct TrainingSample {
    pub timestamp: DateTime<Utc>,
    pub features: Vec<f64>,
    pub source_ip: String,
    pub event_type: String,
    pub is_labeled_anomaly: Option<bool>,
    pub raw_log: String,
}

/// Extractor de características
pub trait FeatureExtractor {
    fn extract_features(&self, log_event: &LogEventFeatures) -> Result<Vec<f64>>;
    fn feature_names(&self) -> Vec<String>;
    fn feature_count(&self) -> usize;
}

/// Características de evento de log para ML
#[derive(Debug, Clone)]
pub struct LogEventFeatures {
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub request_size: usize,
    pub response_size: usize,
    pub response_time_ms: Option<u64>,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
    pub request_method: Option<String>,
    pub request_path: Option<String>,
    pub protocol: Option<String>,
    pub referer: Option<String>,
    pub payload_entropy: f64,
    pub special_char_count: usize,
    pub keyword_matches: usize,
}

/// Resultado de detección de anomalías ML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyMLResult {
    pub is_anomaly: bool,
    pub anomaly_score: f64,
    pub confidence: f64,
    pub model_predictions: HashMap<String, f64>,
    pub feature_importance: Vec<FeatureImportance>,
    pub similar_events: Vec<SimilarEvent>,
    pub risk_level: RiskLevel,
    pub explanations: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Importancia de características
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureImportance {
    pub feature_name: String,
    pub importance_score: f64,
    pub contribution: f64,
    pub is_anomalous: bool,
}

/// Evento similar encontrado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarEvent {
    pub similarity_score: f64,
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub event_type: String,
    pub was_anomaly: bool,
}

/// Rendimiento del modelo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPerformance {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub false_positive_rate: f64,
    pub training_samples: usize,
    pub last_evaluation: Option<DateTime<Utc>>,
}
impl Default for ModelPerformance {
    fn default() -> Self {
        Self {
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            false_positive_rate: 0.0,
            training_samples: 0,
            last_evaluation: None,
        }
    }
}

/// Estadísticas del detector ML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLStatistics {
    pub total_predictions: u64,
    pub anomalies_detected: u64,
    pub false_positives: u64,
    pub true_positives: u64,
    pub model_retrainings: u64,
    pub average_prediction_time_ms: f64,
    pub feature_statistics: HashMap<String, FeatureStats>,
}
impl Default for MLStatistics {
    fn default() -> Self {
        Self {
            total_predictions: 0,
            anomalies_detected: 0,
            false_positives: 0,
            true_positives: 0,
            model_retrainings: 0,
            average_prediction_time_ms: 0.0,
            feature_statistics: HashMap::new(),
        }
    }
}

/// Estadísticas de características
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub percentile_95: f64,
}

/// Niveles de riesgo
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for AnomalyMLConfig {
    fn default() -> Self {
        Self {
            training_window_hours: 24,
            min_training_samples: 1000,
            retrain_interval_hours: 6,
            anomaly_threshold: 0.7,
            isolation_forest_contamination: 0.1,
            kmeans_clusters: 5,
            feature_scaling: true,
            online_learning: true,
            ensemble_voting: true,
        }
    }
}

impl AnomalyMLDetector {
    pub fn new() -> Self {
        Self::with_config(AnomalyMLConfig::default())
    }

    pub fn with_config(config: AnomalyMLConfig) -> Self {
        let feature_extractors: Vec<Box<dyn FeatureExtractor + Send + Sync>> = vec![
            Box::new(BasicFeatureExtractor::new()),
            Box::new(TemporalFeatureExtractor::new()),
            Box::new(PayloadFeatureExtractor::new()),
            Box::new(NetworkFeatureExtractor::new()),
            Box::new(BehavioralFeatureExtractor::new()),
        ];

        Self {
            models: Arc::new(RwLock::new(MLModels {
                false_positive_classifier: None,
                anomaly_detector: None,
                similarity_matcher: None,
                last_training: None,
                model_performance: ModelPerformance::default(),
            })),
            feature_extractors,
            training_data: Arc::new(RwLock::new(TrainingDataBuffer {
                samples: VecDeque::new(),
                max_size: config.min_training_samples * 5,
                last_cleanup: Utc::now(),
            })),
            config,
            statistics: Arc::new(RwLock::new(MLStatistics::default())),
        }
    }

    /// Detecta anomalías en un evento de log
    pub fn detect_anomaly(&self, log_features: &LogEventFeatures) -> Result<AnomalyMLResult> {
        let start_time = std::time::Instant::now();

        // Extraer características
        let features = self.extract_all_features(log_features)?;

        // Verificar si los modelos están entrenados
        let models = self.models.read().unwrap();
        if models.false_positive_classifier.is_none() && models.anomaly_detector.is_none() {
            drop(models);
            // Intentar entrenar si tenemos suficientes datos
            if self.should_retrain()? {
                self.train_models()?;
            } else {
                return Ok(self.create_untrained_result());
            }
        } else {
            drop(models);
        }

        // Realizar predicciones
        let model_predictions = self.predict_with_ensemble(&features)?;

        // Calcular score de anomalía final
        let anomaly_score = self.calculate_ensemble_score(&model_predictions);
        let is_anomaly = anomaly_score >= self.config.anomaly_threshold;

        // Calcular importancia de características
        let feature_importance = self.calculate_feature_importance(&features, anomaly_score)?;

        // Buscar eventos similares
        let similar_events = self.find_similar_events(&features)?;

        // Determinar nivel de riesgo
        let risk_level = self.determine_risk_level(anomaly_score, &feature_importance);

        // Generar explicaciones
        let explanations = self.generate_explanations(anomaly_score, &feature_importance, &similar_events);

        // Generar recomendaciones
        let recommendations = self.generate_recommendations(&feature_importance, risk_level.clone());

        // Calcular confianza
        let confidence = self.calculate_confidence(&model_predictions, &similar_events);

        // Actualizar estadísticas
        self.update_statistics(start_time.elapsed().as_millis() as f64, is_anomaly);

        // Agregar a buffer de entrenamiento para aprendizaje online
        if self.config.online_learning {
            self.add_training_sample(log_features, &features, is_anomaly)?;
        }

        Ok(AnomalyMLResult {
            is_anomaly,
            anomaly_score,
            confidence,
            model_predictions,
            feature_importance,
            similar_events,
            risk_level,
            explanations,
            recommendations,
        })
    }

    /// Entrena los modelos ML
    pub fn train_models(&self) -> Result<()> {
        let training_data = self.training_data.read().unwrap();
        
        if training_data.samples.len() < self.config.min_training_samples {
            return Err(anyhow::anyhow!("Insufficient training samples: {} < {}", 
                training_data.samples.len(), self.config.min_training_samples));
        }

        // Entrenar modelo de falsos positivos
        let fp_model = self.train_false_positive_model(&training_data.samples)?;
        
        // Entrenar detector de anomalías básico
        let anomaly_detector = self.train_basic_anomaly_detector(&training_data.samples)?;
        
        // Entrenar matcher de similitud
        let similarity_matcher = self.train_similarity_matcher(&training_data.samples)?;
        
        // Actualizar modelos
        let mut models = self.models.write().unwrap();
        models.false_positive_classifier = Some(fp_model);
        models.anomaly_detector = Some(anomaly_detector);
        models.similarity_matcher = Some(similarity_matcher);
        models.last_training = Some(Utc::now());
        
        // Evaluar rendimiento
        models.model_performance = self.evaluate_model_performance_real(&training_data.samples)?;
        
        drop(models);
        drop(training_data);
        
        let mut stats = self.statistics.write().unwrap();
        stats.model_retrainings += 1;
        
        tracing::info!("ML models trained successfully with {} samples", self.training_data.read().unwrap().samples.len());
        
        Ok(())
    }
    
    /// Entrena modelo de clasificación de falsos positivos
    fn train_false_positive_model(&self, samples: &VecDeque<TrainingSample>) -> Result<FalsePositiveModel> {
        let mut feature_thresholds = HashMap::new();
        let mut whitelist_patterns = Vec::new();
        
        // Analizar muestras marcadas como falsos positivos
        let fp_samples: Vec<_> = samples.iter()
            .filter(|s| s.is_labeled_anomaly == Some(false))
            .collect();
            
        if fp_samples.len() < 10 {
            tracing::warn!("Few false positive samples for training: {}", fp_samples.len());
        }
        
        // Calcular umbrales de características basados en falsos positivos
        let feature_names = self.get_all_feature_names();
        for (i, feature_name) in feature_names.iter().enumerate() {
            let fp_values: Vec<f64> = fp_samples.iter()
                .filter_map(|s| s.features.get(i).copied())
                .collect();
                
            if !fp_values.is_empty() {
                let mean = fp_values.iter().sum::<f64>() / fp_values.len() as f64;
                let variance = fp_values.iter()
                    .map(|x| (x - mean).powi(2))
                    .sum::<f64>() / fp_values.len() as f64;
                let std_dev = variance.sqrt();
                
                // Umbral: media ± 2 desviaciones estándar
                feature_thresholds.insert(feature_name.clone(), mean + 2.0 * std_dev);
            }
        }
        
        // Generar patrones de whitelist basados en falsos positivos comunes
        for sample in &fp_samples {
            if sample.source_ip.starts_with("192.168.") || sample.source_ip.starts_with("10.") {
                whitelist_patterns.push(WhitelistPattern {
                    pattern_type: "internal_ip".to_string(),
                    pattern_value: sample.source_ip.clone(),
                    confidence: 0.9,
                    created_at: Utc::now(),
                    times_matched: 1,
                });
            }
            
            if sample.event_type.contains("clean file") {
                whitelist_patterns.push(WhitelistPattern {
                    pattern_type: "clean_file_upload".to_string(),
                    pattern_value: sample.event_type.clone(),
                    confidence: 0.95,
                    created_at: Utc::now(),
                    times_matched: 1,
                });
            }
        }
        
        Ok(FalsePositiveModel {
            feature_thresholds,
            whitelist_patterns,
            confidence_threshold: 0.7,
            training_data_size: samples.len(),
        })
    }
    
    /// Entrena detector de anomalías básico
    fn train_basic_anomaly_detector(&self, samples: &VecDeque<TrainingSample>) -> Result<BasicAnomalyDetector> {
        let normal_samples: Vec<_> = samples.iter()
            .filter(|s| s.is_labeled_anomaly != Some(true))
            .collect();
            
        if normal_samples.is_empty() {
            return Err(anyhow::anyhow!("No normal samples available for training"));
        }
        
        // Calcular baseline de comportamiento normal
        let feature_count = normal_samples[0].features.len();
        let mut baseline = vec![0.0; feature_count];
        
        for sample in &normal_samples {
            for (i, &feature) in sample.features.iter().enumerate() {
                baseline[i] += feature;
            }
        }
        
        for value in &mut baseline {
            *value /= normal_samples.len() as f64;
        }
        
        // Generar centros de cluster usando k-means simple
        let cluster_centers = self.simple_kmeans(&normal_samples, 3)?;
        
        // Calcular umbral de distancia
        let distances: Vec<f64> = normal_samples.iter()
            .map(|sample| {
                cluster_centers.iter()
                    .map(|center| self.calculate_euclidean_distance(&sample.features, center))
                    .fold(f64::INFINITY, f64::min)
            })
            .collect();
            
        let mean_distance = distances.iter().sum::<f64>() / distances.len() as f64;
        let distance_threshold = mean_distance * 2.0; // 2x la distancia promedio
        
        Ok(BasicAnomalyDetector {
            cluster_centers,
            distance_threshold,
            normal_behavior_baseline: baseline,
        })
    }
    
    /// Implementación simple de k-means
    fn simple_kmeans(&self, samples: &[&TrainingSample], k: usize) -> Result<Vec<Vec<f64>>> {
        if samples.is_empty() {
            return Err(anyhow::anyhow!("No samples for clustering"));
        }
        
        let feature_count = samples[0].features.len();
        let mut centers = Vec::new();
        
        // Inicializar centros aleatoriamente
        for i in 0..k {
            let sample_idx = i * samples.len() / k;
            centers.push(samples[sample_idx].features.clone());
        }
        
        // Iterar para refinar centros
        for _ in 0..10 {
            let mut new_centers = vec![vec![0.0; feature_count]; k];
            let mut cluster_counts = vec![0; k];
            
            // Asignar muestras a clusters
            for sample in samples {
                let closest_cluster = centers.iter()
                    .enumerate()
                    .min_by(|(_, c1), (_, c2)| {
                        self.calculate_euclidean_distance(&sample.features, c1)
                            .partial_cmp(&self.calculate_euclidean_distance(&sample.features, c2))
                            .unwrap()
                    })
                    .map(|(idx, _)| idx)
                    .unwrap();
                    
                for (i, &feature) in sample.features.iter().enumerate() {
                    new_centers[closest_cluster][i] += feature;
                }
                cluster_counts[closest_cluster] += 1;
            }
            
            // Actualizar centros
            for (i, center) in new_centers.iter_mut().enumerate() {
                if cluster_counts[i] > 0 {
                    for value in center.iter_mut() {
                        *value /= cluster_counts[i] as f64;
                    }
                }
            }
            
            centers = new_centers;
        }
        
        Ok(centers)
    }
    
    /// Entrena matcher de similitud
    fn train_similarity_matcher(&self, samples: &VecDeque<TrainingSample>) -> Result<SimilarityMatcher> {
        let mut known_false_positives = Vec::new();
        
        let fp_samples: Vec<_> = samples.iter()
            .filter(|s| s.is_labeled_anomaly == Some(false))
            .collect();
            
        for sample in fp_samples {
            let signature = EventSignature {
                features_hash: self.hash_features(&sample.features),
                source_pattern: self.extract_source_pattern(&sample.source_ip),
                event_type_pattern: sample.event_type.clone(),
                payload_fingerprint: self.create_payload_fingerprint(&sample.raw_log),
                marked_fp_count: 1,
                last_seen: sample.timestamp,
            };
            known_false_positives.push(signature);
        }
        
        Ok(SimilarityMatcher {
            known_false_positives,
            similarity_threshold: 0.85,
        })
    }
    
    /// Hash de características para comparación rápida
    fn hash_features(&self, features: &[f64]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        for &feature in features {
            ((feature * 1000.0) as i64).hash(&mut hasher);
        }
        format!("{:x}", hasher.finish())
    }
    
    /// Extrae patrón de IP origen
    fn extract_source_pattern(&self, ip: &str) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 3 {
            format!("{}.{}.{}.*", parts[0], parts[1], parts[2])
        } else {
            ip.to_string()
        }
    }
    
    /// Crea fingerprint del payload
    fn create_payload_fingerprint(&self, payload: &str) -> String {
        // Crear fingerprint basado en patrones clave
        let mut fingerprint = String::new();
        
        if payload.contains("GET") { fingerprint.push_str("GET:"); }
        if payload.contains("POST") { fingerprint.push_str("POST:"); }
        if payload.contains("clean file") { fingerprint.push_str("CLEAN_FILE:"); }
        if payload.contains("success") { fingerprint.push_str("SUCCESS:"); }
        if payload.contains("/api/") { fingerprint.push_str("API:"); }
        
        fingerprint
    }
    /// Extrae todas las características de un evento
    fn extract_all_features(&self, log_features: &LogEventFeatures) -> Result<Vec<f64>> {
        let mut all_features = Vec::new();

        for extractor in &self.feature_extractors {
            let features = extractor.extract_features(log_features)
                .context("Error extracting features")?;
            all_features.extend(features);
        }

        Ok(all_features)
    }

    /// Realiza predicciones con ensemble de modelos incluyendo detección de falsos positivos
    fn predict_with_ensemble(&self, features: &[f64]) -> Result<HashMap<String, f64>> {
        let mut predictions = HashMap::new();
        let models = self.models.read().unwrap();

        // Verificar falsos positivos primero
        if let Some(ref fp_model) = models.false_positive_classifier {
            let fp_score = self.predict_false_positive(features, fp_model)?;
            predictions.insert("false_positive_score".to_string(), fp_score);
        }

        // Detector de anomalías básico
        if let Some(ref anomaly_detector) = models.anomaly_detector {
            let anomaly_score = self.predict_anomaly_basic(features, anomaly_detector)?;
            predictions.insert("anomaly_score".to_string(), anomaly_score);
        }

        // Si no hay modelos entrenados, usar fallback simple
        if predictions.is_empty() {
            let feature_sum: f64 = features.iter().sum();
            let feature_avg = feature_sum / features.len() as f64;
            let fallback_score = (feature_avg / 10.0).min(1.0).max(0.0);
            predictions.insert("fallback_score".to_string(), fallback_score);
        }

        Ok(predictions)
    }
    
    /// Predice probabilidad de falso positivo
    fn predict_false_positive(&self, features: &[f64], fp_model: &FalsePositiveModel) -> Result<f64> {
        let feature_names = self.get_all_feature_names();
        let mut fp_indicators = 0.0;
        let mut total_checks = 0.0;
        
        // Verificar umbrales de características
        for (i, &feature_value) in features.iter().enumerate() {
            if let Some(feature_name) = feature_names.get(i) {
                if let Some(&threshold) = fp_model.feature_thresholds.get(feature_name) {
                    total_checks += 1.0;
                    if feature_value <= threshold {
                        fp_indicators += 1.0;
                    }
                }
            }
        }
        
        let threshold_score = if total_checks > 0.0 {
            fp_indicators / total_checks
        } else {
            0.5
        };
        
        // Verificar patrones de whitelist
        let whitelist_score = if !fp_model.whitelist_patterns.is_empty() {
            0.3 // Score base si hay patrones en whitelist
        } else {
            0.0
        };
        
        // Combinar scores
        let combined_score: f64 = threshold_score * 0.7 + whitelist_score * 0.3;
        Ok(combined_score.min(1.0))
    }
    
    /// Predice anomalía usando detector básico
    fn predict_anomaly_basic(&self, features: &[f64], detector: &BasicAnomalyDetector) -> Result<f64> {
        // Calcular distancia mínima a centros de cluster
        let min_distance = detector.cluster_centers.iter()
            .map(|center| self.calculate_euclidean_distance(features, center))
            .fold(f64::INFINITY, f64::min);
            
        // Normalizar distancia contra umbral
        let normalized_distance = (min_distance / detector.distance_threshold).min(2.0);
        
        // Calcular desviación del baseline
        let baseline_deviation = features.iter()
            .zip(&detector.normal_behavior_baseline)
            .map(|(&feature, &baseline)| ((feature - baseline) / (baseline + 1.0)).abs())
            .sum::<f64>() / features.len() as f64;
            
        // Combinar métricas
        let anomaly_score = (normalized_distance * 0.6 + baseline_deviation * 0.4).min(1.0);
        
        Ok(anomaly_score)
    }

    /// Calcula score de ensemble considerando falsos positivos
    fn calculate_ensemble_score(&self, predictions: &HashMap<String, f64>) -> f64 {
        if predictions.is_empty() {
            return 0.0;
        }

        // Si hay score de falso positivo alto, reducir score de anomalía
        let fp_score = predictions.get("false_positive_score").unwrap_or(&0.0);
        let anomaly_score = predictions.get("anomaly_score").unwrap_or(&0.0);
        let fallback_score = predictions.get("fallback_score").unwrap_or(&0.0);

        if *fp_score > 0.7 {
            // Alta probabilidad de falso positivo - reducir score dramáticamente
            return (*anomaly_score * (1.0 - fp_score)).max(0.1);
        }

        if self.config.ensemble_voting {
            // Voting promediado ponderado con ajuste por falsos positivos
            let mut total_score = 0.0;
            let mut total_weight = 0.0;

            for (model, score) in predictions {
                let weight: f64 = match model.as_str() {
                    "false_positive_score" => -0.8, // Peso negativo para FP
                    "anomaly_score" => 0.7,
                    "fallback_score" => 0.3,
                    _ => 0.1,
                };
                
                if model == "false_positive_score" {
                    total_score -= score * weight.abs(); // Restar falsos positivos
                } else {
                    total_score += score * weight;
                    total_weight += weight;
                }
            }

            (total_score / total_weight.max(0.1)).max(0.0).min(1.0)
        } else {
            // Tomar anomaly score ajustado por FP
            let base_anomaly = anomaly_score.max(*fallback_score);
            (base_anomaly * (1.0 - fp_score * 0.5)).max(0.0)
        }
    }

    /// Calcula importancia de características
    fn calculate_feature_importance(&self, features: &[f64], anomaly_score: f64) -> Result<Vec<FeatureImportance>> {
        let mut importance_scores = Vec::new();
        let feature_names = self.get_all_feature_names();

        for (i, &feature_value) in features.iter().enumerate() {
            let feature_name = feature_names.get(i)
                .unwrap_or(&format!("feature_{}", i))
                .clone();

            // Calcular importancia basada en desviación de la normalidad
            let stats = self.get_feature_statistics(&feature_name);
            let normalized_value = if stats.std_dev > 0.0 {
                (feature_value - stats.mean) / stats.std_dev
            } else {
                0.0
            };

            let importance_score = normalized_value.abs() / 3.0; // 3-sigma rule
            let contribution = normalized_value * anomaly_score;
            let is_anomalous = importance_score > 0.5;

            importance_scores.push(FeatureImportance {
                feature_name,
                importance_score,
                contribution,
                is_anomalous,
            });
        }

        // Ordenar por importancia
        importance_scores.sort_by(|a, b| b.importance_score.partial_cmp(&a.importance_score).unwrap());

        Ok(importance_scores)
    }

    /// Busca eventos similares
    fn find_similar_events(&self, features: &[f64]) -> Result<Vec<SimilarEvent>> {
        let training_data = self.training_data.read().unwrap();
        let mut similar_events = Vec::new();

        for sample in training_data.samples.iter().rev().take(100) {
            let similarity = self.calculate_cosine_similarity(features, &sample.features);

            if similarity > 0.8 { // Umbral de similitud
                similar_events.push(SimilarEvent {
                    similarity_score: similarity,
                    timestamp: sample.timestamp,
                    source_ip: sample.source_ip.clone(),
                    event_type: sample.event_type.clone(),
                    was_anomaly: sample.is_labeled_anomaly.unwrap_or(false),
                });
            }
        }

        // Ordenar por similitud
        similar_events.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap());
        similar_events.truncate(5); // Mantener solo los 5 más similares

        Ok(similar_events)
    }

    /// Determina nivel de riesgo
    fn determine_risk_level(&self, anomaly_score: f64, feature_importance: &[FeatureImportance]) -> RiskLevel {
        let critical_features = feature_importance.iter()
            .filter(|f| f.is_anomalous && f.importance_score > 0.8)
            .count();

        if anomaly_score >= 0.9 || critical_features >= 3 {
            RiskLevel::Critical
        } else if anomaly_score >= 0.7 || critical_features >= 2 {
            RiskLevel::High
        } else if anomaly_score >= 0.4 || critical_features >= 1 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    /// Genera explicaciones para la detección
    fn generate_explanations(&self, anomaly_score: f64, feature_importance: &[FeatureImportance], similar_events: &[SimilarEvent]) -> Vec<String> {
        let mut explanations = Vec::new();

        explanations.push(format!("Score de anomalía: {:.3}", anomaly_score));

        // Explicaciones basadas en características
        let anomalous_features: Vec<_> = feature_importance.iter()
            .filter(|f| f.is_anomalous)
            .take(3)
            .collect();

        if !anomalous_features.is_empty() {
            explanations.push("Características anómalas detectadas:".to_string());
            for feature in anomalous_features {
                explanations.push(format!(
                    "- {}: importancia {:.3}, contribución {:.3}",
                    feature.feature_name,
                    feature.importance_score,
                    feature.contribution
                ));
            }
        }

        // Explicaciones basadas en eventos similares
        if !similar_events.is_empty() {
            let anomalous_similar = similar_events.iter()
                .filter(|e| e.was_anomaly)
                .count();

            if anomalous_similar > 0 {
                explanations.push(format!(
                    "Encontrados {} eventos similares previos, {} fueron anomalías",
                    similar_events.len(),
                    anomalous_similar
                ));
            } else {
                explanations.push(format!(
                    "Encontrados {} eventos similares, ninguno fue anomalía (posible falso positivo)",
                    similar_events.len()
                ));
            }
        } else {
            explanations.push("No se encontraron eventos similares en el historial".to_string());
        }

        explanations
    }

    /// Genera recomendaciones
    fn generate_recommendations(&self, feature_importance: &[FeatureImportance], risk_level: RiskLevel) -> Vec<String> {
        let mut recommendations = Vec::new();

        match risk_level {
            RiskLevel::Critical => {
                recommendations.push("CRÍTICO: Investigar inmediatamente".to_string());
                recommendations.push("Bloquear tráfico sospechoso si es posible".to_string());
                recommendations.push("Alertar al equipo de seguridad".to_string());
            },
            RiskLevel::High => {
                recommendations.push("ALTO: Revisar en las próximas 2 horas".to_string());
                recommendations.push("Monitorear actividad relacionada".to_string());
            },
            RiskLevel::Medium => {
                recommendations.push("MEDIO: Revisar durante el día".to_string());
                recommendations.push("Documentar para análisis de tendencias".to_string());
            },
            RiskLevel::Low => {
                recommendations.push("BAJO: Monitoreo rutinario".to_string());
            },
        }

        // Recomendaciones específicas por características
        for feature in feature_importance.iter().take(3).filter(|f| f.is_anomalous) {
            match feature.feature_name.as_str() {
                name if name.contains("payload_entropy") => {
                    recommendations.push("Analizar payload por posible obfuscación".to_string());
                },
                name if name.contains("request_frequency") => {
                    recommendations.push("Implementar rate limiting para esta IP".to_string());
                },
                name if name.contains("user_agent") => {
                    recommendations.push("Verificar legitimidad del User-Agent".to_string());
                },
                name if name.contains("response_time") => {
                    recommendations.push("Investigar posible ataque de timing".to_string());
                },
                _ => {}
            }
        }

        recommendations
    }

    /// Calcula confianza en la predicción
    fn calculate_confidence(&self, predictions: &HashMap<String, f64>, similar_events: &[SimilarEvent]) -> f64 {
        let mut confidence = 0.5; // Base confidence

        // Incrementar confianza si múltiples modelos concuerdan
        if predictions.len() > 1 {
            let scores: Vec<f64> = predictions.values().cloned().collect();
            let mean_score = scores.iter().sum::<f64>() / scores.len() as f64;
            let variance = scores.iter()
                .map(|s| (s - mean_score).powi(2))
                .sum::<f64>() / scores.len() as f64;

            // Baja varianza = alta confianza
            confidence += (1.0 - variance).max(0.0) * 0.3;
        }

        // Incrementar confianza si hay eventos similares
        if !similar_events.is_empty() {
            let avg_similarity = similar_events.iter()
                .map(|e| e.similarity_score)
                .sum::<f64>() / similar_events.len() as f64;
            confidence += avg_similarity * 0.2;
        }

        confidence.min(1.0)
    }

    /// Verifica si debe reentrenar los modelos
    fn should_retrain(&self) -> Result<bool> {
        let models = self.models.read().unwrap();
        let training_data = self.training_data.read().unwrap();

        // Reentrenar si no hay modelos
        if models.false_positive_classifier.is_none() && models.anomaly_detector.is_none() {
            return Ok(training_data.samples.len() >= self.config.min_training_samples);
        }

        // Reentrenar por intervalo de tiempo
        if let Some(last_training) = models.last_training {
            let time_since_training = Utc::now().signed_duration_since(last_training);
            if time_since_training.num_hours() >= self.config.retrain_interval_hours as i64 {
                return Ok(true);
            }
        }

        // Reentrenar si hay suficientes nuevos datos
        let new_samples_threshold = self.config.min_training_samples / 4;
        Ok(training_data.samples.len() > models.model_performance.training_samples + new_samples_threshold)
    }

    /// Prepara datos de entrenamiento
    fn prepare_training_data(&self, samples: &VecDeque<TrainingSample>) -> Result<(DenseMatrix<f64>, Vec<i32>)> {
        let mut features_vec = Vec::new();
        let mut labels = Vec::new();

        for sample in samples.iter() {
            features_vec.extend_from_slice(&sample.features);
            labels.push(if sample.is_labeled_anomaly.unwrap_or(false) { 1 } else { 0 });
        }

        let n_samples = samples.len();
        let n_features = if n_samples > 0 {
            samples[0].features.len()
        } else {
            return Err(anyhow::anyhow!("No samples available"));
        };

        let mut features_2d = Vec::new();
        for i in 0..n_samples {
            let start = i * n_features;
            let end = start + n_features;
            features_2d.push(features_vec[start..end].to_vec());
        }
        let features_matrix = DenseMatrix::from_2d_vec(&features_2d)?;

        Ok((features_matrix, labels))
    }
    /// Evalúa rendimiento del modelo con datos reales
    fn evaluate_model_performance_real(&self, samples: &VecDeque<TrainingSample>) -> Result<ModelPerformance> {
        if samples.len() < 10 {
            return Ok(ModelPerformance::default());
        }
        
        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut true_negatives = 0;
        let mut false_negatives = 0;
        
        // Usar muestras etiquetadas para evaluación
        for sample in samples.iter() {
            if let Some(is_labeled_anomaly) = sample.is_labeled_anomaly {
                let prediction_result = self.predict_with_ensemble(&sample.features);
                if let Ok(predictions) = prediction_result {
                    let anomaly_score = self.calculate_ensemble_score(&predictions);
                    let predicted_anomaly = anomaly_score >= self.config.anomaly_threshold;
                    
                    match (is_labeled_anomaly, predicted_anomaly) {
                        (true, true) => true_positives += 1,
                        (false, true) => false_positives += 1,
                        (false, false) => true_negatives += 1,
                        (true, false) => false_negatives += 1,
                    }
                }
            }
        }
        
        let total = (true_positives + false_positives + true_negatives + false_negatives) as f64;
        if total == 0.0 {
            return Ok(ModelPerformance::default());
        }
        
        let accuracy = (true_positives + true_negatives) as f64 / total;
        let precision = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else { 0.0 };
        let recall = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else { 0.0 };
        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else { 0.0 };
        let false_positive_rate = if false_positives + true_negatives > 0 {
            false_positives as f64 / (false_positives + true_negatives) as f64
        } else { 0.0 };
        
        Ok(ModelPerformance {
            accuracy,
            precision,
            recall,
            f1_score,
            false_positive_rate,
            training_samples: samples.len(),
            last_evaluation: Some(Utc::now()),
        })
    }
    /// Funciones auxiliares
    fn calculate_euclidean_distance(&self, a: &[f64], b: &[f64]) -> f64 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    fn calculate_cosine_similarity(&self, a: &[f64], b: &[f64]) -> f64 {
        let dot_product: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f64 = a.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();
        let norm_b: f64 = b.iter().map(|x| x.powi(2)).sum::<f64>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot_product / (norm_a * norm_b)
        }
    }

    fn get_all_feature_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        for extractor in &self.feature_extractors {
            names.extend(extractor.feature_names());
        }
        names
    }

    fn get_feature_statistics(&self, feature_name: &str) -> FeatureStats {
        let stats = self.statistics.read().unwrap();
        stats.feature_statistics
            .get(feature_name)
            .cloned()
            .unwrap_or_default()
    }

    fn add_training_sample(&self, log_features: &LogEventFeatures, features: &[f64], is_anomaly: bool) -> Result<()> {
        let sample = TrainingSample {
            timestamp: log_features.timestamp,
            features: features.to_vec(),
            source_ip: log_features.source_ip.clone(),
            event_type: "web_request".to_string(), // Podría ser más específico
            is_labeled_anomaly: Some(is_anomaly),
            raw_log: format!("{} {} {}",
                             log_features.source_ip,
                             log_features.request_method.as_deref().unwrap_or("UNKNOWN"),
                             log_features.request_path.as_deref().unwrap_or("/")
            ),
        };

        let mut training_data = self.training_data.write().unwrap();
        training_data.samples.push_back(sample);

        // Limpiar buffer si excede el tamaño máximo
        while training_data.samples.len() > training_data.max_size {
            training_data.samples.pop_front();
        }

        Ok(())
    }

    fn update_statistics(&self, prediction_time_ms: f64, is_anomaly: bool) {
        let mut stats = self.statistics.write().unwrap();
        stats.total_predictions += 1;

        if is_anomaly {
            stats.anomalies_detected += 1;
        }

        // Actualizar tiempo promedio de predicción
        let total_time = stats.average_prediction_time_ms * (stats.total_predictions - 1) as f64;
        stats.average_prediction_time_ms = (total_time + prediction_time_ms) / stats.total_predictions as f64;
    }

    fn create_untrained_result(&self) -> AnomalyMLResult {
        AnomalyMLResult {
            is_anomaly: false,
            anomaly_score: 0.0,
            confidence: 0.0,
            model_predictions: HashMap::new(),
            feature_importance: Vec::new(),
            similar_events: Vec::new(),
            risk_level: RiskLevel::Low,
            explanations: vec!["Modelos no entrenados - datos insuficientes".to_string()],
            recommendations: vec!["Recopilar más datos para entrenamiento".to_string()],
        }
    }

    /// Métodos públicos adicionales

    /// Obtiene estadísticas del detector
    pub fn get_statistics(&self) -> MLStatistics {
        self.statistics.read().unwrap().clone()
    }

    /// Obtiene información de los modelos
    pub fn get_model_info(&self) -> serde_json::Value {
        let models = self.models.read().unwrap();
        let stats = self.statistics.read().unwrap();
        serde_json::json!({
           "models_trained": models.false_positive_classifier.is_some() || models.anomaly_detector.is_some(),
           "false_positive_classifier_active": models.false_positive_classifier.is_some(),
           "anomaly_detector_active": models.anomaly_detector.is_some(),
           "similarity_matcher_active": models.similarity_matcher.is_some(),
           "last_training": models.last_training,
           "performance": models.model_performance,
           "training_samples": models.model_performance.training_samples,
           "total_predictions": stats.total_predictions,
           "false_positives_detected": stats.false_positives,
           "true_positives": stats.true_positives,
           "model_retrainings": stats.model_retrainings,
           "avg_prediction_time_ms": stats.average_prediction_time_ms
       })
    }
    
    /// Marca un evento como falso positivo para reentrenamiento
    pub fn mark_as_false_positive(&self, event_id: &str, log_features: &LogEventFeatures) -> Result<()> {
        let features = self.extract_all_features(log_features)?;
        
        // Crear muestra marcada como falso positivo
        let sample = TrainingSample {
            timestamp: log_features.timestamp,
            features,
            source_ip: log_features.source_ip.clone(),
            event_type: format!("marked_fp_{}", event_id),
            is_labeled_anomaly: Some(false), // Marcar explícitamente como NO anomalía
            raw_log: format!("FP: {} - {}", event_id, log_features.request_path.as_deref().unwrap_or("unknown")),
        };
        
        // Agregar al buffer de entrenamiento
        let mut training_data = self.training_data.write().unwrap();
        training_data.samples.push_back(sample);
        
        // Actualizar estadísticas
        let mut stats = self.statistics.write().unwrap();
        stats.false_positives += 1;
        
        tracing::info!("Event {} marked as false positive", event_id);
        
        // Verificar si necesitamos reentrenar
        if self.should_retrain_for_fp()? {
            drop(training_data);
            drop(stats);
            self.retrain_for_false_positives()?;
        }
        
        Ok(())
    }
    
    /// Verifica si debe reentrenar por falsos positivos
    fn should_retrain_for_fp(&self) -> Result<bool> {
        let training_data = self.training_data.read().unwrap();
        let stats = self.statistics.read().unwrap();
        
        // Reentrenar si hay muchos falsos positivos recientes
        let recent_fp_count = training_data.samples.iter()
            .filter(|s| s.is_labeled_anomaly == Some(false))
            .filter(|s| s.timestamp > Utc::now() - Duration::hours(1))
            .count();
            
        Ok(recent_fp_count >= 5 || stats.false_positives % 10 == 0)
    }
    
    /// Reentrenamiento específico para falsos positivos
    pub fn retrain_for_false_positives(&self) -> Result<()> {
        tracing::info!("Retraining models due to false positive feedback");
        self.train_models()
    }
    
    /// Obtiene patrones de falsos positivos detectados
    pub fn get_false_positive_patterns(&self) -> serde_json::Value {
        let models = self.models.read().unwrap();
        
        if let Some(ref fp_model) = models.false_positive_classifier {
            serde_json::json!({
                "whitelist_patterns": fp_model.whitelist_patterns,
                "feature_thresholds": fp_model.feature_thresholds,
                "confidence_threshold": fp_model.confidence_threshold,
                "training_data_size": fp_model.training_data_size
            })
        } else {
            serde_json::json!({
                "message": "False positive classifier not yet trained"
            })
        }
    }
    
    /// Simula detección de falsos positivos para eventos comunes
    pub fn simulate_false_positive_detection(&self) -> Vec<String> {
        vec![
            "File upload scanner: clean file detected - commonly flagged as false positive".to_string(),
            "Internal IP 192.168.1.* requests - often legitimate traffic".to_string(),
            "API endpoint /api/users/profile - normal user behavior".to_string(),
            "Successful authentication events - legitimate user access".to_string(),
            "GET requests to static resources - normal web traffic".to_string(),
        ]
    }

    /// Limpia datos antiguos del buffer
    pub fn cleanup_old_data(&self) {
        let cutoff_time = Utc::now() - Duration::hours(self.config.training_window_hours as i64 * 2);

        let mut training_data = self.training_data.write().unwrap();
        while let Some(front) = training_data.samples.front() {
            if front.timestamp < cutoff_time {
                training_data.samples.pop_front();
            } else {
                break;
            }
        }
        training_data.last_cleanup = Utc::now();
    }

    /// Exporta modelo entrenado
    pub fn export_model(&self) -> Result<serde_json::Value> {
        let models = self.models.read().unwrap();
        let stats = self.statistics.read().unwrap();

        Ok(serde_json::json!({
           "export_timestamp": Utc::now(),
           "model_performance": models.model_performance,
           "statistics": *stats,
           "config": self.config,
           "feature_names": self.get_all_feature_names()
       }))
    }
}

impl Default for AnomalyMLDetector {
    fn default() -> Self {
        Self::new()
    }
}


/// Extractor de características básicas
pub struct BasicFeatureExtractor;

impl BasicFeatureExtractor {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for BasicFeatureExtractor {
    fn extract_features(&self, log_event: &LogEventFeatures) -> Result<Vec<f64>> {
        let mut features = Vec::new();

        // Tamaño de request normalizado (log scale)
        features.push((log_event.request_size as f64 + 1.0).ln());

        // Tamaño de response normalizado (log scale)
        features.push((log_event.response_size as f64 + 1.0).ln());

        // Tiempo de respuesta normalizado
        let response_time = log_event.response_time_ms.unwrap_or(100) as f64;
        features.push((response_time + 1.0).ln());

        // Código de estado (normalizado)
        let status_code = log_event.status_code.unwrap_or(200) as f64;
        features.push(status_code / 1000.0);

        // Entropía del payload
        features.push(log_event.payload_entropy);

        // Número de caracteres especiales normalizado
        features.push((log_event.special_char_count as f64).ln());

        // Número de palabras clave coincidentes
        features.push(log_event.keyword_matches as f64);

        Ok(features)
    }

    fn feature_names(&self) -> Vec<String> {
        vec![
            "log_request_size".to_string(),
            "log_response_size".to_string(),
            "log_response_time".to_string(),
            "status_code_normalized".to_string(),
            "payload_entropy".to_string(),
            "log_special_chars".to_string(),
            "keyword_matches".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        7
    }
}

/// Extractor de características temporales
pub struct TemporalFeatureExtractor {
    request_history: Arc<RwLock<HashMap<String, VecDeque<DateTime<Utc>>>>>,
}

impl TemporalFeatureExtractor {
    pub fn new() -> Self {
        Self {
            request_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn update_request_history(&self, ip: &str, timestamp: DateTime<Utc>) {
        let mut history = self.request_history.write().unwrap();
        let ip_history = history.entry(ip.to_string()).or_insert_with(VecDeque::new);

        // Agregar nuevo timestamp
        ip_history.push_back(timestamp);

        // Limpiar timestamps antiguos (más de 1 hora)
        let cutoff = timestamp - Duration::hours(1);
        while let Some(&front) = ip_history.front() {
            if front < cutoff {
                ip_history.pop_front();
            } else {
                break;
            }
        }

        // Limitar tamaño del historial
        while ip_history.len() > 1000 {
            ip_history.pop_front();
        }
    }
}

impl FeatureExtractor for TemporalFeatureExtractor {
    fn extract_features(&self, log_event: &LogEventFeatures) -> Result<Vec<f64>> {
        let mut features = Vec::new();

        // Actualizar historial
        self.update_request_history(&log_event.source_ip, log_event.timestamp);

        let history = self.request_history.read().unwrap();
        let ip_history = history.get(&log_event.source_ip);

        if let Some(ip_history) = ip_history {
            // Frecuencia de requests en la última hora
            let requests_last_hour = ip_history.len() as f64;
            features.push(requests_last_hour.ln());

            // Frecuencia de requests en los últimos 10 minutos
            let ten_minutes_ago = log_event.timestamp - Duration::minutes(10);
            let requests_last_10min = ip_history.iter()
                .filter(|&&ts| ts > ten_minutes_ago)
                .count() as f64;
            features.push(requests_last_10min.ln());

            // Tiempo desde el último request
            if let Some(&last_request) = ip_history.iter().rev().nth(1) {
                let time_since_last = log_event.timestamp
                    .signed_duration_since(last_request)
                    .num_seconds() as f64;
                features.push((time_since_last + 1.0).ln());
            } else {
                features.push(0.0);
            }

            // Variabilidad en intervalos entre requests
            if ip_history.len() >= 3 {
                let intervals: Vec<f64> = ip_history.iter()
                    .rev()
                    .take(10)
                    .collect::<Vec<_>>()
                    .windows(2)
                    .map(|w| w[0].signed_duration_since(*w[1]).num_seconds() as f64)
                    .collect();

                let mean_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
                let variance = intervals.iter()
                    .map(|x| (x - mean_interval).powi(2))
                    .sum::<f64>() / intervals.len() as f64;

                features.push(variance.sqrt());
            } else {
                features.push(0.0);
            }
        } else {
            // Primera vez que vemos esta IP
            features.extend(vec![0.0, 0.0, 0.0, 0.0]);
        }

        // Hora del día (normalizada)
        let hour = log_event.timestamp.hour() as f64 / 24.0;
        features.push(hour);

        // Día de la semana (normalizado)
        let weekday = log_event.timestamp.weekday().num_days_from_monday() as f64 / 7.0;
        features.push(weekday);

        Ok(features)
    }

    fn feature_names(&self) -> Vec<String> {
        vec![
            "log_requests_last_hour".to_string(),
            "log_requests_last_10min".to_string(),
            "log_time_since_last".to_string(),
            "request_interval_variance".to_string(),
            "hour_of_day".to_string(),
            "day_of_week".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        6
    }
}

/// Extractor de características de payload
pub struct PayloadFeatureExtractor;

impl PayloadFeatureExtractor {
    pub fn new() -> Self {
        Self
    }

    fn calculate_string_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts: HashMap<char, usize> = HashMap::new();
        for ch in s.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for &count in char_counts.values() {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }

        entropy
    }
}

impl FeatureExtractor for PayloadFeatureExtractor {
    fn extract_features(&self, log_event: &LogEventFeatures) -> Result<Vec<f64>> {
        let mut features = Vec::new();

        // Analizar User-Agent si está disponible
        if let Some(user_agent) = &log_event.user_agent {
            features.push(self.calculate_string_entropy(user_agent));
            features.push(user_agent.len() as f64);

            // Verificar si es un User-Agent común/conocido
            let common_ua_patterns = [
                "Mozilla", "Chrome", "Safari", "Firefox", "Edge", "Opera"
            ];
            let is_common = common_ua_patterns.iter()
                .any(|pattern| user_agent.contains(pattern));
            features.push(if is_common { 0.0 } else { 1.0 });
        } else {
            features.extend(vec![0.0, 0.0, 1.0]); // Sin User-Agent es sospechoso
        }

        // Analizar path de request
        if let Some(path) = &log_event.request_path {
            features.push(self.calculate_string_entropy(path));
            features.push(path.len() as f64);
            features.push(path.matches('/').count() as f64); // Profundidad del path
            features.push(path.matches('?').count() as f64); // Número de query strings
            features.push(path.matches('&').count() as f64); // Número de parámetros

            // Detectar caracteres sospechosos
            let suspicious_chars = ['<', '>', '"', '\'', ';', '(', ')', '{', '}'];
            let suspicious_count = path.chars()
                .filter(|&c| suspicious_chars.contains(&c))
                .count() as f64;
            features.push(suspicious_count);
        } else {
            features.extend(vec![0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        }

        // Analizar referer
        if let Some(referer) = &log_event.referer {
            if referer != "-" {
                features.push(self.calculate_string_entropy(referer));
                features.push(referer.len() as f64);
            } else {
                features.extend(vec![0.0, 0.0]);
            }
        } else {
            features.extend(vec![0.0, 0.0]);
        }

        Ok(features)
    }

    fn feature_names(&self) -> Vec<String> {
        vec![
            "user_agent_entropy".to_string(),
            "user_agent_length".to_string(),
            "user_agent_uncommon".to_string(),
            "path_entropy".to_string(),
            "path_length".to_string(),
            "path_depth".to_string(),
            "query_strings_count".to_string(),
            "parameters_count".to_string(),
            "suspicious_chars_count".to_string(),
            "referer_entropy".to_string(),
            "referer_length".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        11
    }
}

/// Extractor de características de red
pub struct NetworkFeatureExtractor;

impl NetworkFeatureExtractor {
    pub fn new() -> Self {
        Self
    }

    fn is_private_ip(&self, ip: &str) -> bool {
        ip.starts_with("192.168.") ||
            ip.starts_with("10.") ||
            ip.starts_with("172.") ||
            ip.starts_with("127.")
    }

    fn get_ip_class(&self, ip: &str) -> f64 {
        if let Some(first_octet) = ip.split('.').next() {
            if let Ok(octet) = first_octet.parse::<u8>() {
                match octet {
                    1..=126 => 1.0,   // Class A
                    128..=191 => 2.0, // Class B
                    192..=223 => 3.0, // Class C
                    224..=239 => 4.0, // Class D (Multicast)
                    240..=255 => 5.0, // Class E (Reserved)
                    _ => 0.0,
                }
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
}

impl FeatureExtractor for NetworkFeatureExtractor {
    fn extract_features(&self, log_event: &LogEventFeatures) -> Result<Vec<f64>> {
        let mut features = Vec::new();

        // Características de IP
        features.push(if self.is_private_ip(&log_event.source_ip) { 1.0 } else { 0.0 });
        features.push(self.get_ip_class(&log_event.source_ip));

        // Análisis del protocolo
        let protocol_score = match log_event.protocol.as_deref() {
            Some("HTTP/1.1") => 1.0,
            Some("HTTP/1.0") => 2.0,
            Some("HTTP/2.0") => 0.5,
            Some(p) if p.starts_with("HTTP") => 3.0,
            _ => 4.0, // Protocolo desconocido
        };
        features.push(protocol_score);

        // Análisis del método HTTP
        let method_score = match log_event.request_method.as_deref() {
            Some("GET") => 1.0,
            Some("POST") => 1.5,
            Some("PUT") => 2.0,
            Some("DELETE") => 2.5,
            Some("OPTIONS") => 3.0,
            Some("HEAD") => 1.2,
            Some("TRACE") => 4.0, // Método peligroso
            Some("CONNECT") => 4.0, // Método peligroso
            _ => 3.0,
        };
        features.push(method_score);

        Ok(features)
    }

    fn feature_names(&self) -> Vec<String> {
        vec![
            "is_private_ip".to_string(),
            "ip_class".to_string(),
            "protocol_risk_score".to_string(),
            "method_risk_score".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        4
    }
}

/// Extractor de características de comportamiento
pub struct BehavioralFeatureExtractor {
    behavior_cache: Arc<RwLock<HashMap<String, UserBehavior>>>,
}

#[derive(Debug, Clone)]
struct UserBehavior {
    typical_user_agents: HashMap<String, u32>,
    typical_paths: HashMap<String, u32>,
    typical_methods: HashMap<String, u32>,
    avg_request_size: f64,
    avg_response_time: f64,
    last_updated: DateTime<Utc>,
}

impl BehavioralFeatureExtractor {
    pub fn new() -> Self {
        Self {
            behavior_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn update_user_behavior(&self, log_event: &LogEventFeatures) {
        let mut cache = self.behavior_cache.write().unwrap();
        let behavior = cache.entry(log_event.source_ip.clone())
            .or_insert_with(|| UserBehavior {
                typical_user_agents: HashMap::new(),
                typical_paths: HashMap::new(),
                typical_methods: HashMap::new(),
                avg_request_size: 0.0,
                avg_response_time: 0.0,
                last_updated: log_event.timestamp,
            });

        // Actualizar patrones
        if let Some(ua) = &log_event.user_agent {
            *behavior.typical_user_agents.entry(ua.clone()).or_insert(0) += 1;
        }

        if let Some(path) = &log_event.request_path {
            *behavior.typical_paths.entry(path.clone()).or_insert(0) += 1;
        }

        if let Some(method) = &log_event.request_method {
            *behavior.typical_methods.entry(method.clone()).or_insert(0) += 1;
        }

        // Actualizar promedios (simple moving average)
        behavior.avg_request_size = (behavior.avg_request_size + log_event.request_size as f64) / 2.0;
        if let Some(rt) = log_event.response_time_ms {
            behavior.avg_response_time = (behavior.avg_response_time + rt as f64) / 2.0;
        }

        behavior.last_updated = log_event.timestamp;
    }
}

impl FeatureExtractor for BehavioralFeatureExtractor {
    fn extract_features(&self, log_event: &LogEventFeatures) -> Result<Vec<f64>> {
        // Actualizar comportamiento del usuario
        self.update_user_behavior(log_event);

        let mut features = Vec::new();
        let cache = self.behavior_cache.read().unwrap();

        if let Some(behavior) = cache.get(&log_event.source_ip) {
            // Desviación del User-Agent típico
            let ua_deviation = if let Some(ua) = &log_event.user_agent {
                let ua_count = behavior.typical_user_agents.get(ua).unwrap_or(&0);
                let total_ua = behavior.typical_user_agents.values().sum::<u32>().max(1);
                1.0 - (*ua_count as f64 / total_ua as f64)
            } else {
                1.0 // Sin UA es desviación máxima
            };
            features.push(ua_deviation);

            // Desviación del path típico
            let path_deviation = if let Some(path) = &log_event.request_path {
                let path_count = behavior.typical_paths.get(path).unwrap_or(&0);
                let total_paths = behavior.typical_paths.values().sum::<u32>().max(1);
                1.0 - (*path_count as f64 / total_paths as f64)
            } else {
                0.5
            };
            features.push(path_deviation);

            // Desviación del método típico
            let method_deviation = if let Some(method) = &log_event.request_method {
                let method_count = behavior.typical_methods.get(method).unwrap_or(&0);
                let total_methods = behavior.typical_methods.values().sum::<u32>().max(1);
                1.0 - (*method_count as f64 / total_methods as f64)
            } else {
                0.5
            };
            features.push(method_deviation);

            // Desviación del tamaño de request
            let size_deviation = if behavior.avg_request_size > 0.0 {
                (log_event.request_size as f64 - behavior.avg_request_size).abs() / behavior.avg_request_size
            } else {
                0.0
            };
            features.push(size_deviation.min(10.0)); // Cap at 10x deviation

            // Desviación del tiempo de respuesta
            let time_deviation = if let Some(rt) = log_event.response_time_ms {
                if behavior.avg_response_time > 0.0 {
                    (rt as f64 - behavior.avg_response_time).abs() / behavior.avg_response_time
                } else {
                    0.0
                }
            } else {
                0.0
            };
            features.push(time_deviation.min(10.0)); // Cap at 10x deviation
        } else {
            // Primera vez viendo este usuario
            features.extend(vec![1.0, 1.0, 1.0, 1.0, 1.0]);
        }

        Ok(features)
    }

    fn feature_names(&self) -> Vec<String> {
        vec![
            "user_agent_deviation".to_string(),
            "path_deviation".to_string(),
            "method_deviation".to_string(),
            "request_size_deviation".to_string(),
            "response_time_deviation".to_string(),
        ]
    }

    fn feature_count(&self) -> usize {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_feature_extraction() {
        let extractor = BasicFeatureExtractor::new();
        let log_event = LogEventFeatures {
            timestamp: Utc::now(),
            source_ip: "192.168.1.100".to_string(),
            request_size: 1024,
            response_size: 2048,
            response_time_ms: Some(150),
            status_code: Some(200),
            user_agent: Some("Mozilla/5.0".to_string()),
            request_method: Some("GET".to_string()),
            request_path: Some("/test".to_string()),
            protocol: Some("HTTP/1.1".to_string()),
            referer: Some("-".to_string()),
            payload_entropy: 3.2,
            special_char_count: 5,
            keyword_matches: 2,
        };

        let features = extractor.extract_features(&log_event).unwrap();
        assert_eq!(features.len(), extractor.feature_count());
        assert!(features.iter().all(|&f| f.is_finite()));
    }

    #[test]
    fn test_anomaly_detection_basic() {
        let detector = AnomalyMLDetector::new();

        let log_event = LogEventFeatures {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".to_string(),
            request_size: 100,
            response_size: 200,
            response_time_ms: Some(50),
            status_code: Some(200),
            user_agent: Some("Mozilla/5.0".to_string()),
            request_method: Some("GET".to_string()),
            request_path: Some("/".to_string()),
            protocol: Some("HTTP/1.1".to_string()),
            referer: None,
            payload_entropy: 2.0,
            special_char_count: 0,
            keyword_matches: 0,
        };

        // Sin entrenamiento debería retornar resultado por defecto
        let result = detector.detect_anomaly(&log_event).unwrap();
        assert!(!result.is_anomaly);
        assert_eq!(result.anomaly_score, 0.0);
    }

    #[test]
    fn test_feature_extractors() {
        let temporal_extractor = TemporalFeatureExtractor::new();
        let payload_extractor = PayloadFeatureExtractor::new();
        let network_extractor = NetworkFeatureExtractor::new();
        let behavioral_extractor = BehavioralFeatureExtractor::new();

        let log_event = LogEventFeatures {
            timestamp: Utc::now(),
            source_ip: "192.168.1.100".to_string(),
            request_size: 500,
            response_size: 1000,
            response_time_ms: Some(100),
            status_code: Some(200),
            user_agent: Some("curl/7.68.0".to_string()),
            request_method: Some("POST".to_string()),
            request_path: Some("/api/test?param=value".to_string()),
            protocol: Some("HTTP/1.1".to_string()),
            referer: Some("https://example.com".to_string()),
            payload_entropy: 4.5,
            special_char_count: 3,
            keyword_matches: 1,
        };

        // Probar cada extractor
        let temporal_features = temporal_extractor.extract_features(&log_event).unwrap();
        assert_eq!(temporal_features.len(), temporal_extractor.feature_count());

        let payload_features = payload_extractor.extract_features(&log_event).unwrap();
        assert_eq!(payload_features.len(), payload_extractor.feature_count());

        let network_features = network_extractor.extract_features(&log_event).unwrap();
        assert_eq!(network_features.len(), network_extractor.feature_count());

        let behavioral_features = behavioral_extractor.extract_features(&log_event).unwrap();
        assert_eq!(behavioral_features.len(), behavioral_extractor.feature_count());
    }

    #[test]
    fn test_entropy_calculation() {
        let extractor = PayloadFeatureExtractor::new();

        // String con baja entropía
        let low_entropy = extractor.calculate_string_entropy("aaaaaaaa");
        assert!(low_entropy < 1.0);

        // String con alta entropía
        let high_entropy = extractor.calculate_string_entropy("aB3$x9@Z");
        assert!(high_entropy > 2.0);
    }

    #[test]
    fn test_model_training_insufficient_data() {
        let detector = AnomalyMLDetector::new();

        // Intentar entrenar sin datos suficientes
        let result = detector.train_models();
        assert!(result.is_err());
    }

    #[test]
    fn test_statistics_tracking() {
        let detector = AnomalyMLDetector::new();

        // Simular algunas predicciones
        detector.update_statistics(10.0, true);
        detector.update_statistics(15.0, false);
        detector.update_statistics(12.0, true);

        let stats = detector.get_statistics();
        assert_eq!(stats.total_predictions, 3);
        assert_eq!(stats.anomalies_detected, 2);
        assert!(stats.average_prediction_time_ms > 0.0);
    }
}
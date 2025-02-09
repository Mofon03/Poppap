import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, balanced_accuracy_score
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Tuple
import os
import pickle
from collections import Counter

# Page configuration
st.set_page_config(page_title="NIST CSF 2.0 Assessment System", layout="wide")

# Constants
NIST_FUNCTIONS = {
    'identify': {
        'categories': ['ID.AM', 'ID.BE', 'ID.GV', 'ID.RA', 'ID.RM', 'ID.SC'],
        'keywords': ['asset', 'inventory', 'configuration', 'business', 'risk'],
        'controls_keywords': ['compliance', 'configuration', 'asset', 'risk'],
        'weight': 1.5  # ปรับเพิ่มน้ำหนัก
    },
    'protect': {
        'categories': ['PR.AC', 'PR.DS', 'PR.IP', 'PR.MA', 'PR.PT'],
        'keywords': ['access control', 'encryption', 'firewall', 'authentication'],
        'controls_keywords': ['access', 'authentication', 'encryption', 'firewall'],
        'weight': 1.5  # ปรับเพิ่มน้ำหนัก
    },
    'detect': {
        'categories': ['DE.AE', 'DE.CM', 'DE.DP'],
        'keywords': ['monitoring', 'anomalies', 'detection', 'alerts'],
        'controls_keywords': ['ids', 'monitoring', 'detection', 'analysis'],
        'weight': 1.2
    },
    'respond': {
        'categories': ['RS.RP', 'RS.CO', 'RS.AN', 'RS.MI', 'RS.IM'],
        'keywords': ['incident', 'response', 'mitigation', 'communication'],
        'controls_keywords': ['incident', 'response', 'patch', 'update'],
        'weight': 1.0
    },
    'recover': {
        'categories': ['RC.RP', 'RC.IM', 'RC.CO'],
        'keywords': ['recovery', 'backup', 'restore', 'resilience'],
        'controls_keywords': ['backup', 'recovery', 'continuity', 'restore'],
        'weight': 0.8
    },
    'govern': {
        'categories': ['GV.PL', 'GV.RM', 'GV.IM', 'GV.CM'],
        'keywords': ['policy', 'governance', 'compliance', 'management'],
        'controls_keywords': ['policy', 'governance', 'compliance', 'audit'],
        'weight': 1.0
    }
}

IMPLEMENTATION_TIERS = {
    'Tier 1': {
        'name': 'Partial',
        'range': (1.0, 2.0),
        'description': 'Limited awareness and ad hoc implementation',
        'characteristics': [
            'Risk management practices are not formalized',
            'Limited awareness of cybersecurity risks',
            'Response to threats is reactive'
        ]
    },
    'Tier 2': {
        'name': 'Risk Informed',
        'range': (2.0, 3.0),
        'description': 'Risk informed, but policies not formalized',
        'characteristics': [
            'Risk management exists but not organization-wide',
            'Increased awareness of cybersecurity risks',
            'Some proactive capabilities exist'
        ]
    },
    'Tier 3': {
        'name': 'Repeatable',
        'range': (3.0, 3.5),
        'description': 'Formally approved and implemented policies',
        'characteristics': [
            'Organization-wide risk management policies',
            'Regular cybersecurity practices',
            'Consistent response procedures'
        ]
    },
    'Tier 4': {
        'name': 'Adaptive',
        'range': (3.5, 4.0),
        'description': 'Adaptive and proactive implementation',
        'characteristics': [
            'Continuous improvement of cybersecurity practices',
            'Active risk management',
            'Proactive threat response'
        ]
    }
}

ATTACK_SCENARIOS = {
    'Ransomware Attack': {
        'description': 'Simulation of a ransomware attack targeting critical systems',
        'progression_stages': [
            'Initial Access through Phishing',
            'Lateral Movement and Privilege Escalation',
            'Data Encryption and System Lock',
            'Ransom Demand'
        ],
        'impact_factors': {
            'identify': 0.7,
            'protect': 0.8,
            'detect': 0.6,
            'respond': 0.5,
            'recover': 0.4,
            'govern': 0.3
        }
    },
    'Supply Chain Attack': {
        'description': 'Simulation of a compromise through third-party software',
        'progression_stages': [
            'Vendor System Compromise',
            'Malicious Update Distribution',
            'Backdoor Installation',
            'Data Exfiltration'
        ],
        'impact_factors': {
            'identify': 0.8,
            'protect': 0.7,
            'detect': 0.6,
            'respond': 0.5,
            'recover': 0.4,
            'govern': 0.6
        }
    },
    'Phishing Attack': {
        'description': 'Simulation of a targeted phishing campaign',
        'progression_stages': [
            'Email Distribution',
            'Credential Harvest',
            'Account Compromise',
            'Data Breach'
        ],
        'impact_factors': {
            'identify': 0.5,
            'protect': 0.7,
            'detect': 0.6,
            'respond': 0.5,
            'recover': 0.3,
            'govern': 0.4
        }
    },
    'DDoS Attack': {
        'description': 'Simulation of a distributed denial of service attack',
        'progression_stages': [
            'Initial Traffic Surge',
            'Service Degradation',
            'System Overload',
            'Service Disruption'
        ],
        'impact_factors': {
            'identify': 0.4,
            'protect': 0.6,
            'detect': 0.7,
            'respond': 0.6,
            'recover': 0.5,
            'govern': 0.3
        }
    }
}
# Core functions
def parse_nessus_file(file_path: str) -> Dict:
    """Parse Nessus scan file with improved mapping."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        vulnerabilities = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        security_metrics = {
            func: {'controls': 0, 'findings': 0} 
            for func in NIST_FUNCTIONS.keys()
        }

        # Process each report item
        for report_host in root.findall('.//ReportHost'):
            for item in report_host.findall('.//ReportItem'):
                process_report_item(item, vulnerabilities, security_metrics)

        return {
            'status': 'success',
            'vulnerabilities': vulnerabilities,
            'security_metrics': security_metrics,
            'filename': os.path.basename(file_path),
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        return {
            'status': 'error',
            'message': str(e),
            'filename': os.path.basename(file_path)
        }

def process_report_item(item, vulnerabilities: Dict, metrics: Dict):
    """Process individual Nessus report items with improved severity mapping."""
    # Map severity with increased weights
    severity = item.get('severity')
    if severity == '4':
        vulnerabilities['Critical'] += 2.0  # เพิ่มน้ำหนัก
    elif severity == '3':
        vulnerabilities['High'] += 1.5     # เพิ่มน้ำหนัก
    elif severity == '2':
        vulnerabilities['Medium'] += 1.0
    elif severity == '1':
        vulnerabilities['Low'] += 0.5
    elif severity == '0':
        vulnerabilities['Info'] += 0.2

    # Extract item information
    plugin_name = item.get('pluginName', '').lower()
    plugin_family = item.get('pluginFamily', '').lower()
    plugin_text = f"{plugin_name} {plugin_family}"

    # Map to NIST functions with improved accuracy
    for func, data in NIST_FUNCTIONS.items():
        # Check for controls
        if any(keyword in plugin_text for keyword in data['controls_keywords']):
            metrics[func]['controls'] += 1
            
        # Add findings based on severity and keywords
        if severity in ['3', '4'] or any(keyword in plugin_text for keyword in data['keywords']):
            metrics[func]['findings'] += 1.5 if severity in ['3', '4'] else 1.0

def calculate_nist_scores(nessus_data: Dict) -> Dict[str, float]:
    """Calculate NIST CSF scores with improved accuracy."""
    scores = {}
    vulnerabilities = nessus_data['vulnerabilities']
    metrics = nessus_data['security_metrics']

    # Calculate base score
    total_vulns = sum(vulnerabilities.values())
    if total_vulns == 0:
        base_score = 2.5  # ลดลงจาก 3.0
    else:
        # ปรับน้ำหนักช่องโหว่
        weights = {
            'Critical': 2.0,  # เพิ่มน้ำหนัก critical
            'High': 1.5,      # เพิ่มน้ำหนัก high
            'Medium': 0.8,    # ปรับน้ำหนัก medium
            'Low': 0.2,
            'Info': 0.0
        }
        weighted_sum = sum(vulnerabilities[sev] * weights[sev] for sev in vulnerabilities)
        base_score = 2.5 - (weighted_sum / (total_vulns * 0.8))  # ปรับสูตร

    # Calculate function-specific scores
    for function in NIST_FUNCTIONS.keys():
        metrics_data = metrics[function]
        
        # Calculate control score
        control_score = min(0.8, metrics_data['controls'] / 15)  # ปรับลดค่าสูงสุด
        
        # Calculate finding penalty
        finding_penalty = min(1.5, metrics_data['findings'] / 30) if metrics_data['findings'] > 0 else 0
        
        # Calculate final score
        weight = NIST_FUNCTIONS[function]['weight']
        function_score = (base_score + control_score - finding_penalty) * weight
        
        # Normalize to 1-4 range
        function_score = max(1.0, min(4.0, function_score))
        scores[function] = round(function_score, 2)

    return scores

def determine_tier(scores: Dict[str, float]) -> str:
    """Determine Implementation Tier with improved weighting."""
    # Calculate weighted average score
    weighted_sum = sum(scores[func] * NIST_FUNCTIONS[func]['weight'] 
                      for func in NIST_FUNCTIONS.keys())
    total_weight = sum(func_data['weight'] for func_data in NIST_FUNCTIONS.values())
    avg_score = weighted_sum / total_weight

    # ปรับเกณฑ์การกำหนด Tier
    if avg_score >= 3.75:  # เพิ่มเกณฑ์
        return 'Tier 4'
    elif avg_score >= 3.25:  # ปรับเกณฑ์
        return 'Tier 3'
    elif avg_score >= 2.5:  # ปรับเกณฑ์
        return 'Tier 2'
    else:
        return 'Tier 1'

def simulate_attack(current_scores: Dict[str, float], attack_type: str) -> Dict:
    """Simulate attack impact on scores."""
    impact_factors = ATTACK_SCENARIOS[attack_type]['impact_factors']
    post_attack_scores = {}
    impact = {}

    for func in current_scores.keys():
        # Calculate impact
        impact[func] = current_scores[func] * impact_factors[func]
        # Calculate post-attack score
        post_attack_scores[func] = max(1.0, current_scores[func] - impact[func])
        post_attack_scores[func] = round(post_attack_scores[func], 2)

    return {
        'original_scores': current_scores,
        'post_attack_scores': post_attack_scores,
        'impact': impact,
        'attack_type': attack_type
    }
# Assessment Model Class
class NISTAssessmentModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.history = self.load_history()
        self.iterations = self.load_iterations()

    def load_history(self):
        if os.path.exists('history.pkl'):
            with open('history.pkl', 'rb') as f:
                return pickle.load(f)
        return []

    def save_history(self):
        with open('history.pkl', 'wb') as f:
            pickle.dump(self.history, f)

    def load_iterations(self):
        if os.path.exists('iterations.txt'):
            with open('iterations.txt', 'r') as f:
                return int(f.read())
        return 0

    def save_iterations(self):
        with open('iterations.txt', 'w') as f:
            f.write(str(self.iterations))

    def prepare_data(self, nessus_files: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data with enhanced feature engineering."""
        X = []
        y = []
        
        for file_path in nessus_files:
            data = parse_nessus_file(file_path)
            if data['status'] == 'success':
                scores = calculate_nist_scores(data)
                features = self.extract_features(data, scores)
                tier = determine_tier(scores)
                
                X.append(features)
                y.append(tier)

        return np.array(X), np.array(y)

    def extract_features(self, data: Dict, scores: Dict[str, float]) -> List[float]:
        """Extract enhanced feature set for training."""
        features = []

        # Function scores
        features.extend([scores[func] for func in NIST_FUNCTIONS.keys()])

        # Vulnerability counts
        vuln_data = data['vulnerabilities']
        features.extend([vuln_data[sev] for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']])

        # Security metrics
        for func in NIST_FUNCTIONS.keys():
            metrics = data['security_metrics'][func]
            features.append(metrics['controls'])
            features.append(metrics['findings'])
            
            # Add derived metrics
            ratio = metrics['controls'] / max(metrics['findings'], 1)
            features.append(ratio)

        return features

    def balance_data(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Balance dataset using duplicate sampling for minority classes."""
        class_counts = Counter(y)
        max_samples = max(class_counts.values())
        
        X_balanced = []
        y_balanced = []
        
        for tier in class_counts.keys():
            tier_idx = np.where(y == tier)[0]
            n_samples = len(tier_idx)
            
            if n_samples < max_samples:
                n_duplicates = max_samples - n_samples
                duplicate_idx = np.random.choice(tier_idx, size=n_duplicates, replace=True)
                tier_idx = np.concatenate([tier_idx, duplicate_idx])
            
            X_balanced.extend(X[tier_idx])
            y_balanced.extend([tier] * len(tier_idx))
        
        return np.array(X_balanced), np.array(y_balanced)

    def train(self, nessus_files: List[str]) -> Dict:
        """Train model with balanced data and enhanced parameters."""
        X, y = self.prepare_data(nessus_files)
        
        if len(X) < 30:
            return {'status': 'error', 'message': 'Need at least 30 files for training'}

        # Show initial class distribution
        st.write("Initial class distribution:", Counter(y))

        # Balance dataset
        X_balanced, y_balanced = self.balance_data(X, y)
        st.write("Balanced class distribution:", Counter(y_balanced))

        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X_balanced, y_balanced, test_size=0.3, random_state=42, stratify=y_balanced
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
        )

        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)

        # Configure and train model
        param_grid = {
            'n_estimators': [100, 200],
            'max_depth': [None, 10, 20],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [1, 2],
            'class_weight': ['balanced', 'balanced_subsample']
        }

        rf = RandomForestClassifier(random_state=42)
        grid_search = GridSearchCV(rf, param_grid, cv=3, scoring='balanced_accuracy')
        grid_search.fit(X_train_scaled, y_train)

        self.model = grid_search.best_estimator_

        # Evaluate model
        train_acc = balanced_accuracy_score(y_train, self.model.predict(X_train_scaled))
        val_acc = balanced_accuracy_score(y_val, self.model.predict(X_val_scaled))
        test_acc = balanced_accuracy_score(y_test, self.model.predict(X_test_scaled))

        # Save model
        with open('model.pkl', 'wb') as f:
            pickle.dump((self.model, self.scaler), f)

        self.iterations += 1
        self.save_iterations()

        return {
            'status': 'success',
            'train_accuracy': train_acc,
            'val_accuracy': val_acc,
            'test_accuracy': test_acc,
            'best_params': grid_search.best_params_,
            'samples': len(X_balanced)
        }

    def predict(self, data: Dict) -> Dict:
        """Make prediction with detailed analysis."""
        if not self.model:
            if not self.load_model():
                return {'status': 'error', 'message': 'Model not trained'}

        scores = calculate_nist_scores(data)
        features = self.extract_features(data, scores)

        X = np.array([features])
        X_scaled = self.scaler.transform(X)

        tier = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0]
        confidence = max(proba)

        analysis = self.generate_analysis(scores, tier)
        recommendations = self.generate_recommendations(scores, tier)

        assessment = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'scores': scores,
            'tier': tier,
            'confidence': confidence,
            'analysis': analysis,
            'recommendations': recommendations
        }

        self.history.append(assessment)
        self.save_history()

        return assessment

    def generate_analysis(self, scores: Dict[str, float], tier: str) -> Dict:
        """Generate detailed analysis of assessment results."""
        analysis = {}

        # Overall analysis
        analysis['overall'] = {
            'score': sum(scores.values()) / len(scores),
            'tier': tier,
            'description': IMPLEMENTATION_TIERS[tier]['description'],
            'characteristics': IMPLEMENTATION_TIERS[tier]['characteristics']
        }

        # Function-specific analysis
        for func in NIST_FUNCTIONS.keys():
            analysis[func] = {
                'score': scores[func],
                'weight': NIST_FUNCTIONS[func]['weight'],
                'categories': NIST_FUNCTIONS[func]['categories']
            }

        return analysis

    def generate_recommendations(self, scores: Dict[str, float], tier: str) -> List[str]:
        """Generate prioritized recommendations based on scores."""
        recommendations = []
        
        # Sort functions by score (ascending) to prioritize weak areas
        sorted_scores = sorted(scores.items(), key=lambda x: x[1])
        
        for func, score in sorted_scores:
            if score < 2.0:
                recommendations.append(f"Critical: Implement basic {func} controls")
            elif score < 3.0:
                recommendations.append(f"High: Enhance {func} capabilities")
            elif score < 3.5:
                recommendations.append(f"Medium: Optimize {func} processes")
            else:
                recommendations.append(f"Low: Maintain {func} excellence")

        return recommendations

    def load_model(self) -> bool:
        """Load saved model from disk."""
        if os.path.exists('model.pkl'):
            with open('model.pkl', 'rb') as f:
                self.model, self.scaler = pickle.load(f)
            return True
        return False
# UI Functions
def show_upload_section():
    """Handle file upload and model training."""
    st.header("Upload Nessus Files for Training")
    
    if 'uploaded_files' not in st.session_state:
        st.session_state['uploaded_files'] = []

    uploaded_files = st.file_uploader(
        "Upload .nessus files (Minimum 30 required)",
        type=['nessus'],
        accept_multiple_files=True
    )

    if uploaded_files:
        # Check for duplicates
        new_files = []
        existing_names = [f.name for f in st.session_state['uploaded_files']]
        
        for file in uploaded_files:
            if file.name not in existing_names:
                new_files.append(file)
                existing_names.append(file.name)
            else:
                st.warning(f"File {file.name} already uploaded")

        st.session_state['uploaded_files'].extend(new_files)
        
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"Total files: {len(st.session_state['uploaded_files'])}")
        with col2:
            if len(st.session_state['uploaded_files']) >= 30:
                st.success("Minimum requirement met")
            else:
                st.warning(f"Need {30 - len(st.session_state['uploaded_files'])} more files")

        if len(st.session_state['uploaded_files']) >= 30:
            if st.button("Train Model", type="primary"):
                with st.spinner("Training model..."):
                    process_files(st.session_state['uploaded_files'])
                st.session_state['uploaded_files'] = []  # Clear after processing

def process_files(uploaded_files):
    """Process uploaded files and train model."""
    temp_paths = []
    progress = st.progress(0)
    status = st.empty()

    try:
        # Save files temporarily
        for i, file in enumerate(uploaded_files):
            temp_path = f"temp_{file.name}_{i}"
            with open(temp_path, 'wb') as f:
                f.write(file.getvalue())
            temp_paths.append(temp_path)
            progress.progress((i + 1) / len(uploaded_files))
            status.text(f"Processing: {i+1}/{len(uploaded_files)}")

        # Train model
        model = NISTAssessmentModel()
        result = model.train(temp_paths)
        
        if result['status'] == 'success':
            st.session_state['model'] = model
            
            # Show training results
            st.success("Model trained successfully!")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Training Accuracy", f"{result['train_accuracy']:.2%}")
            with col2:
                st.metric("Validation Accuracy", f"{result['val_accuracy']:.2%}")
            with col3:
                st.metric("Test Accuracy", f"{result['test_accuracy']:.2%}")
            
            st.write("Best parameters:", result['best_params'])
        else:
            st.error(result['message'])

    finally:
        # Cleanup
        for path in temp_paths:
            if os.path.exists(path):
                os.remove(path)

def show_assessment_section():
    """Handle individual assessments."""
    st.header("Cybersecurity Assessment")
    
    if 'model' not in st.session_state:
        st.session_state['model'] = NISTAssessmentModel()
        st.session_state['model'].load_model()
    
    if not st.session_state['model'].model:
        st.warning("Please train model first")
        return

    uploaded_file = st.file_uploader("Upload Nessus file for assessment", type=['nessus'])
    if uploaded_file:
        temp_path = f"temp_assessment_{uploaded_file.name}"
        try:
            with open(temp_path, 'wb') as f:
                f.write(uploaded_file.getvalue())
            
            with st.spinner("Analyzing..."):
                data = parse_nessus_file(temp_path)
                if data['status'] == 'success':
                    prediction = st.session_state['model'].predict(data)
                    show_assessment_results(prediction)
                    st.session_state['latest_assessment'] = prediction
                else:
                    st.error(data['message'])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

def show_assessment_results(assessment: Dict):
    """Display assessment results with visualizations."""
    # Overall Results
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("NIST CSF Scores")
        fig = go.Figure(data=go.Scatterpolar(
            r=list(assessment['scores'].values()),
            theta=[f.capitalize() for f in assessment['scores'].keys()],
            fill='toself'
        ))
        fig.update_layout(
            polar={'radialaxis': {'range': [1, 4]}},
            title="Function Scores"
        )
        st.plotly_chart(fig)
    
    with col2:
        st.subheader("Implementation Tier")
        tier_info = IMPLEMENTATION_TIERS[assessment['tier']]
        
        st.metric("Current Tier", f"{tier_info['name']} ({assessment['tier']})")
        st.metric("Confidence", f"{assessment['confidence']:.1%}")
        
        st.write("**Description:**", tier_info['description'])
        
        st.write("**Characteristics:**")
        for char in tier_info['characteristics']:
            st.write(f"- {char}")

    # Detailed Analysis
    st.subheader("Detailed Analysis")
    
    for func in NIST_FUNCTIONS.keys():
        with st.expander(f"{func.capitalize()} Analysis", expanded=(func == 'identify')):
            if func in assessment['analysis']:
                analysis = assessment['analysis'][func]
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Score", f"{analysis['score']:.2f}")
                    st.metric("Weight", f"{NIST_FUNCTIONS[func]['weight']:.1f}")
                with col2:
                    st.write("**Categories:**")
                    for cat in NIST_FUNCTIONS[func]['categories']:
                        st.write(f"- {cat}")

    # Recommendations
    st.subheader("Recommendations")
    recommendations = sorted(
        assessment['recommendations'],
        key=lambda x: (
            0 if x.startswith("Critical") else
            1 if x.startswith("High") else
            2 if x.startswith("Medium") else 3
        )
    )
    for rec in recommendations:
        st.info(rec)

def show_simulation_section():
    """Handle attack simulation scenarios."""
    st.header("Attack Impact Simulation")
    
    if 'latest_assessment' not in st.session_state:
        st.warning("Complete an assessment first")
        return
    
    # Scenario selection
    attack_type = st.selectbox(
        "Select Attack Scenario",
        ["Ransomware Attack", "Supply Chain Attack", "Phishing Attack", "DDoS Attack"]
    )
    
    st.info(ATTACK_SCENARIOS[attack_type]['description'])
    
    # Show progression stages
    with st.expander("Attack Progression"):
        for i, stage in enumerate(ATTACK_SCENARIOS[attack_type]['progression_stages'], 1):
            st.write(f"{i}. {stage}")
    
    if st.button("Run Simulation"):
        with st.spinner("Simulating attack..."):
            result = simulate_attack(
                st.session_state['latest_assessment']['scores'],
                attack_type
            )
            show_simulation_results(result)

def show_simulation_results(result: Dict):
    """Display attack simulation results."""
    st.subheader("Impact Analysis")
    
    # Before/After Comparison
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Before Attack")
        fig1 = go.Figure(data=go.Scatterpolar(
            r=list(result['original_scores'].values()),
            theta=[f.capitalize() for f in result['original_scores'].keys()],
            fill='toself'
        ))
        fig1.update_layout(polar={'radialaxis': {'range': [1, 4]}})
        st.plotly_chart(fig1)
    
    with col2:
        st.subheader("After Attack")
        fig2 = go.Figure(data=go.Scatterpolar(
            r=list(result['post_attack_scores'].values()),
            theta=[f.capitalize() for f in result['post_attack_scores'].keys()],
            fill='toself'
        ))
        fig2.update_layout(polar={'radialaxis': {'range': [1, 4]}})
        st.plotly_chart(fig2)

    # Impact Details
    st.subheader("Detailed Impact Analysis")
    impact_df = pd.DataFrame({
        'Function': [f.capitalize() for f in result['original_scores'].keys()],
        'Before': list(result['original_scores'].values()),
        'After': list(result['post_attack_scores'].values()),
        'Impact': [result['impact'].get(f, 0) for f in result['original_scores'].keys()]
    })
    st.dataframe(impact_df.style.highlight_negative('Impact', axis=0))

    # Post-Attack Analysis
    if 'model' in st.session_state:
        st.subheader("Post-Attack Assessment")
        with st.spinner("Analyzing post-attack state..."):
            post_attack_prediction = st.session_state['model'].predict({
                'scores': result['post_attack_scores'],
                'vulnerabilities': st.session_state['latest_assessment'].get('vulnerabilities', {}),
                'security_metrics': st.session_state['latest_assessment'].get('security_metrics', {})
            })
            
            if post_attack_prediction['status'] == 'success':
                st.write("**New Implementation Tier:**", post_attack_prediction['tier'])
                st.write("**Recommendations for Recovery:**")
                for rec in post_attack_prediction['recommendations']:
                    st.write(f"- {rec}")

def show_history_section():
    """Display assessment history and trends."""
    st.header("Assessment History")
    
    if 'model' not in st.session_state:
        st.session_state['model'] = NISTAssessmentModel()
    
    history = st.session_state['model'].history
    
    if not history:
        st.warning("No assessment history available")
        return
    
    # Summary Statistics
    st.subheader("Assessment Statistics")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Assessments", len(history))
    with col2:
        tiers = [h['tier'] for h in history]
        st.metric("Most Common Tier", max(set(tiers), key=tiers.count))
    with col3:
        avg_score = np.mean([
            sum(h['scores'].values())/len(h['scores']) 
            for h in history
        ])
        st.metric("Average Score", f"{avg_score:.2f}")
    
    # Trend Analysis
    st.subheader("Score Trends")
    trend_data = []
    for h in history:
        for func, score in h['scores'].items():
            trend_data.append({
                'Date': pd.to_datetime(h['timestamp']),
                'Function': func.capitalize(),
                'Score': score
            })
    
    trend_df = pd.DataFrame(trend_data)
    fig = px.line(
        trend_df, 
        x='Date', 
        y='Score', 
        color='Function',
        title='Score Trends Over Time'
    )
    fig.update_layout(yaxis_range=[1, 4])
    st.plotly_chart(fig)
    
    # Detailed History
    st.subheader("Assessment History")
    history_df = pd.DataFrame([
        {
            'Date': h['timestamp'],
            'Tier': h['tier'],
            'Confidence': f"{h['confidence']:.1%}",
            'Average Score': sum(h['scores'].values())/len(h['scores']),
            **{f"{k.capitalize()} Score": v for k, v in h['scores'].items()}
        }
        for h in history
    ])
    st.dataframe(history_df.sort_values('Date', ascending=False))
def main():
    """Main application function."""
    st.title("NIST CSF 2.0 Cybersecurity Assessment System")
    
    # Description
    st.markdown("""
        This system provides AI-powered cybersecurity assessment using the NIST CSF 2.0 framework.
        Upload Nessus scan results for detailed analysis, recommendations, and attack impact simulation.
    """)
    
    # Initialize model if needed
    if 'model' not in st.session_state:
        st.session_state['model'] = NISTAssessmentModel()
        st.session_state['model'].load_model()
    
    # System Stats
    if hasattr(st.session_state['model'], 'history'):
        total_assessments = len(st.session_state['model'].history)
    else:
        total_assessments = 0
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Assessments", total_assessments)
    with col2:
        st.metric("Model Iterations", st.session_state['model'].iterations)
    with col3:
        st.metric("Last Updated", datetime.now().strftime("%Y-%m-%d"))
    
    # Navigation
    menu = ["Assessment", "Attack Simulation", "History", "Upload Files"]
    choice = st.sidebar.selectbox("Select Function", menu)
    
    if choice == "Assessment":
        show_assessment_section()
    elif choice == "Attack Simulation":
        show_simulation_section()
    elif choice == "History":
        show_history_section()
    else:
        show_upload_section()

if __name__ == "__main__":
    main()

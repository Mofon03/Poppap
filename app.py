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

# ---------------------------------------------------------------------
# Streamlit Page Config
# ---------------------------------------------------------------------
st.set_page_config(page_title="NIST CSF 2.0 Assessment System", layout="wide")

# ---------------------------------------------------------------------
# 1) CONSTANTS & DEFINITIONS
# ---------------------------------------------------------------------
NIST_FUNCTIONS = {
    'identify': {
        'categories': ['ID.AM', 'ID.BE', 'ID.GV', 'ID.RA', 'ID.RM', 'ID.SC'],
        'keywords': ['asset', 'inventory', 'configuration', 'business', 'risk'],
        'controls_keywords': ['compliance', 'configuration', 'asset', 'risk'],
        'weight': 1.5
    },
    'protect': {
        'categories': ['PR.AC', 'PR.DS', 'PR.IP', 'PR.MA', 'PR.PT'],
        'keywords': ['access control', 'encryption', 'firewall', 'authentication'],
        'controls_keywords': ['access', 'authentication', 'encryption', 'firewall'],
        'weight': 1.5
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

# ปรับ Impact Factors ให้แตกต่างกันอย่างชัดเจน
ATTACK_SCENARIOS = {
    'Ransomware Attack': {
        'description': 'Simulation of a ransomware attack targeting critical systems',
        'progression_stages': [
            'Initial Access through Phishing',
            'Lateral Movement & Privilege Escalation',
            'Data Encryption and System Lock',
            'Ransom Demand'
        ],
        'impact_factors': {
            'identify': 0.5,
            'protect': 1.0,
            'detect': 0.6,
            'respond': 0.7,
            'recover': 1.0,
            'govern': 0.4
        }
    },
    'Supply Chain Attack': {
        'description': 'Compromise via third-party software',
        'progression_stages': [
            'Vendor System Compromise',
            'Malicious Update Distribution',
            'Backdoor Installation',
            'Data Exfiltration'
        ],
        'impact_factors': {
            'identify': 1.0,
            'protect': 0.5,
            'detect': 0.5,
            'respond': 0.5,
            'recover': 0.4,
            'govern': 1.0
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
            'identify': 0.4,
            'protect': 0.8,
            'detect': 0.7,
            'respond': 0.9,
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
            'identify': 0.3,
            'protect': 0.5,
            'detect': 0.9,
            'respond': 0.8,
            'recover': 0.7,
            'govern': 0.2
        }
    }
}

# ---------------------------------------------------------------------
# 2) PARSING NESSUS & SCORE CALCULATION
# ---------------------------------------------------------------------
def parse_nessus_file(file_path: str) -> Dict:
    """
    Parse Nessus XML and build vulnerabilities + security_metrics.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        vulnerabilities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        security_metrics = {func: {'controls': 0, 'findings': 0} for func in NIST_FUNCTIONS.keys()}

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
    severity = item.get('severity', '0')
    if severity == '4':
        vulnerabilities['Critical'] += 2.0
    elif severity == '3':
        vulnerabilities['High'] += 1.5
    elif severity == '2':
        vulnerabilities['Medium'] += 1.0
    elif severity == '1':
        vulnerabilities['Low'] += 0.5
    elif severity == '0':
        vulnerabilities['Info'] += 0.2

    plugin_name = item.get('pluginName', '').lower()
    plugin_family = item.get('pluginFamily', '').lower()
    plugin_text = f"{plugin_name} {plugin_family}"

    # map to NIST functions
    for func, data in NIST_FUNCTIONS.items():
        if any(kw in plugin_text for kw in data['controls_keywords']):
            metrics[func]['controls'] += 1
        
        # if severity high or critical, or match keywords => +finding
        if severity in ['3','4'] or any(kw in plugin_text for kw in data['keywords']):
            metrics[func]['findings'] += 1.5 if severity in ['3','4'] else 1.0

def calculate_nist_scores(nessus_data: Dict) -> Dict[str, float]:
    vulnerabilities = nessus_data['vulnerabilities']
    metrics = nessus_data['security_metrics']

    total_vuln_score = sum(vulnerabilities.values())
    if total_vuln_score == 0:
        base_score = 2.5
    else:
        # Weighted sum for vulnerabilities
        sev_weight = {'Critical': 2.0, 'High': 1.5, 'Medium': 0.8, 'Low': 0.2, 'Info': 0.0}
        wsum = sum(vulnerabilities[s] * sev_weight[s] for s in vulnerabilities)
        base_score = 2.5 - (wsum / (total_vuln_score * 0.8))

    scores = {}
    for func in NIST_FUNCTIONS.keys():
        m = metrics[func]
        control_score = min(0.8, m['controls'] / 15)
        finding_penalty = min(1.5, m['findings'] / 30) if m['findings']>0 else 0
        w = NIST_FUNCTIONS[func]['weight']

        function_score = (base_score + control_score - finding_penalty) * w
        function_score = max(1.0, min(4.0, function_score))
        scores[func] = round(function_score, 2)

    return scores

def determine_tier(scores: Dict[str, float]) -> str:
    total_weight = sum(f['weight'] for f in NIST_FUNCTIONS.values())
    weighted_sum = sum(scores[f] * NIST_FUNCTIONS[f]['weight'] for f in NIST_FUNCTIONS)
    avg_score = weighted_sum / total_weight

    if avg_score >= 3.75:
        return 'Tier 4'
    elif avg_score >= 3.25:
        return 'Tier 3'
    elif avg_score >= 2.5:
        return 'Tier 2'
    else:
        return 'Tier 1'

# ---------------------------------------------------------------------
# 3) SIMULATE ATTACK (ให้เห็น Impact ต่างกัน)
# ---------------------------------------------------------------------
def simulate_attack(current_scores: Dict[str, float], attack_type: str) -> Dict:
    """
    Use distinct impact_factors for each scenario + multiplier 
    to highlight difference clearly.
    """
    impact_factors = ATTACK_SCENARIOS[attack_type]['impact_factors']
    multiplier = 1.5  # ปรับ multiplier เพื่อให้ผลต่างเด่นชัด
    post_attack_scores = {}
    impact = {}

    for func in current_scores.keys():
        this_impact = current_scores[func] * impact_factors[func] * multiplier
        impact[func] = round(this_impact, 2)
        # ลดคะแนน และกำหนดขั้นต่ำ 0.5 (แทน 1.0) เพื่อแสดงความต่าง
        post_score = current_scores[func] - this_impact
        post_attack_scores[func] = round(max(0.5, post_score), 2)

    return {
        'original_scores': current_scores,
        'post_attack_scores': post_attack_scores,
        'impact': impact,
        'attack_type': attack_type
    }

# ---------------------------------------------------------------------
# 4) MODEL CLASS FOR TRAINING / PREDICT
# ---------------------------------------------------------------------
class NISTAssessmentModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.history = self.load_history()
        self.iterations = self.load_iterations()

    def load_history(self):
        if os.path.exists('history.pkl'):
            with open('history.pkl','rb') as f:
                return pickle.load(f)
        return []

    def save_history(self):
        with open('history.pkl','wb') as f:
            pickle.dump(self.history, f)

    def load_iterations(self):
        if os.path.exists('iterations.txt'):
            with open('iterations.txt','r') as f:
                return int(f.read())
        return 0

    def save_iterations(self):
        with open('iterations.txt','w') as f:
            f.write(str(self.iterations))

    # หมายเหตุ: ฟังก์ชัน train(...) ยังอยู่ในโค้ด
    # แต่จะไม่ถูกเรียกใช้ผ่าน UI แล้ว
    def train(self, nessus_files: List[str]) -> Dict:
        """
        ถ้าต้องการเทรนเองในเครื่องให้เรียกใช้เมธอดนี้ด้วย 
        รายชื่อไฟล์ .nessus แล้วโมเดลจะสร้าง model.pkl ให้
        แต่ในระบบ Production/UI จะไม่แสดงเมนูให้ผู้ใช้เทรนเองแล้ว
        """
        # 1) เตรียมข้อมูล
        X, y = self.prepare_data(nessus_files)
        if len(X)<30:
            return {'status':'error','message':'Need at least 30 files'}

        # ดู distribution
        st.write("Initial class distribution:", Counter(y))

        # 2) Balance data
        Xb, yb = self.balance_data(X,y)
        st.write("Balanced class distribution:", Counter(yb))

        # 3) Train/Val/Test
        X_train, X_temp, y_train, y_temp = train_test_split(Xb, yb, test_size=0.3, random_state=42, stratify=yb)
        X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

        self.scaler = StandardScaler()
        X_train_s = self.scaler.fit_transform(X_train)
        X_val_s = self.scaler.transform(X_val)
        X_test_s = self.scaler.transform(X_test)

        # 4) GridSearch
        param_grid = {
            'n_estimators':[100,200],
            'max_depth':[None,10,20],
            'min_samples_split':[2,5],
            'min_samples_leaf':[1,2],
            'class_weight':['balanced','balanced_subsample']
        }
        rf = RandomForestClassifier(random_state=42)
        gs = GridSearchCV(rf, param_grid, cv=3, scoring='balanced_accuracy')
        gs.fit(X_train_s, y_train)

        self.model = gs.best_estimator_
        train_acc = balanced_accuracy_score(y_train, self.model.predict(X_train_s))
        val_acc = balanced_accuracy_score(y_val, self.model.predict(X_val_s))
        test_acc = balanced_accuracy_score(y_test, self.model.predict(X_test_s))

        # บันทึกโมเดล
        with open('model.pkl','wb') as f:
            pickle.dump((self.model, self.scaler), f)

        self.iterations += 1
        self.save_iterations()

        return {
            'status':'success',
            'train_accuracy': train_acc,
            'val_accuracy': val_acc,
            'test_accuracy': test_acc,
            'best_params': gs.best_params_,
            'samples': len(Xb)
        }

    def prepare_data(self, nessus_files: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        X, y = [], []
        for file_path in nessus_files:
            data = parse_nessus_file(file_path)
            if data['status'] == 'success':
                scores = calculate_nist_scores(data)
                feats = self.extract_features(data, scores)
                tier = determine_tier(scores)
                X.append(feats)
                y.append(tier)
        return np.array(X), np.array(y)

    def extract_features(self, data: Dict, scores: Dict[str, float]) -> List[float]:
        feats = []
        # 1) scores
        for func in NIST_FUNCTIONS.keys():
            feats.append(scores[func])
        # 2) vulnerabilities
        for sev in ['Critical','High','Medium','Low','Info']:
            feats.append(data['vulnerabilities'][sev])
        # 3) security_metrics
        for func in NIST_FUNCTIONS.keys():
            c = data['security_metrics'][func]['controls']
            f = data['security_metrics'][func]['findings']
            feats += [c, f, c/max(f,1)]
        return feats

    def balance_data(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        counts = Counter(y)
        max_samples = max(counts.values())
        X_bal, y_bal = [], []
        for tier in counts.keys():
            idx = np.where(y==tier)[0]
            if len(idx)<max_samples:
                dup = np.random.choice(idx, size=max_samples-len(idx), replace=True)
                idx = np.concatenate([idx, dup])
            X_bal.extend(X[idx])
            y_bal.extend([tier]*len(idx))
        return np.array(X_bal), np.array(y_bal)

    def load_model(self) -> bool:
        if os.path.exists('model.pkl'):
            with open('model.pkl','rb') as f:
                self.model, self.scaler = pickle.load(f)
            return True
        return False

    def predict(self, data: Dict) -> Dict:
        if not self.model:
            if not self.load_model():
                return {'status':'error','message':'Model not trained'}

        # Calculate + extract features
        scores = calculate_nist_scores(data)
        feats = self.extract_features(data,scores)
        X = np.array([feats])
        Xs = self.scaler.transform(X)
        tier = self.model.predict(Xs)[0]
        proba = self.model.predict_proba(Xs)[0]
        confidence = max(proba)

        analysis = self.generate_analysis(scores,tier)
        recs = self.generate_recommendations(scores,tier)

        assessment = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'scores': scores,
            'tier': tier,
            'confidence': confidence,
            'analysis': analysis,
            'recommendations': recs,
            # เก็บ vulnerabilities/metrics ใส่ใน assessment ด้วย (เผื่อใช้ภายหลัง)
            'vulnerabilities': data.get('vulnerabilities', {}),
            'security_metrics': data.get('security_metrics', {})
        }
        self.history.append(assessment)
        self.save_history()
        return assessment

    def generate_analysis(self, scores: Dict[str,float], tier: str) -> Dict:
        analysis={}
        analysis['overall']={
            'score': sum(scores.values())/len(scores),
            'tier': tier,
            'description': IMPLEMENTATION_TIERS[tier]['description'],
            'characteristics': IMPLEMENTATION_TIERS[tier]['characteristics']
        }
        for func in NIST_FUNCTIONS.keys():
            analysis[func] = {
                'score': scores[func],
                'weight': NIST_FUNCTIONS[func]['weight'],
                'categories': NIST_FUNCTIONS[func]['categories']
            }
        return analysis

    def generate_recommendations(self, scores: Dict[str,float], tier: str) -> List[str]:
        recs=[]
        sorted_scores = sorted(scores.items(),key=lambda x:x[1])
        for func,sc in sorted_scores:
            if sc<2.0:
                recs.append(f"Critical: Implement basic {func} controls")
            elif sc<3.0:
                recs.append(f"High: Enhance {func} capabilities")
            elif sc<3.5:
                recs.append(f"Medium: Optimize {func} processes")
            else:
                recs.append(f"Low: Maintain {func} excellence")
        return recs


# ---------------------------------------------------------------------
# 5) STREAMLIT UI - ASSESSMENT
# ---------------------------------------------------------------------
def show_assessment_section():
    st.header("Cybersecurity Assessment")

    # โหลดโมเดล (ถ้ายังไม่มีใน session_state)
    if 'model' not in st.session_state:
        st.session_state['model'] = NISTAssessmentModel()
        st.session_state['model'].load_model()

    # ถ้าโมเดลยังโหลดไม่ได้ => เตือน
    if not st.session_state['model'].model:
        st.warning("No trained model found. Please prepare a valid model.pkl in the same folder.")
        return

    # ส่วนอัปโหลดไฟล์ .nessus สำหรับประเมิน
    uploaded = st.file_uploader("Upload Nessus for assessment", type=['nessus'])
    if uploaded:
        path = f"temp_assessment_{uploaded.name}"
        try:
            with open(path,'wb') as f:
                f.write(uploaded.getvalue())
            with st.spinner("Analyzing..."):
                data = parse_nessus_file(path)
                if data['status'] == 'success':
                    pred = st.session_state['model'].predict(data)
                    show_assessment_results(pred)
                    st.session_state['latest_assessment'] = pred
                else:
                    st.error(data['message'])
        finally:
            if os.path.exists(path):
                os.remove(path)

def show_assessment_results(assessment: Dict):
    c1,c2 = st.columns(2)
    with c1:
        st.subheader("NIST CSF Scores")
        fig = go.Figure(data=go.Scatterpolar(
            r=list(assessment['scores'].values()),
            theta=[f.capitalize() for f in assessment['scores'].keys()],
            fill='toself'
        ))
        fig.update_layout(polar={'radialaxis':{'range':[1,4]}}, title="Function Scores")
        st.plotly_chart(fig)

    with c2:
        st.subheader("Implementation Tier")
        tier_info = IMPLEMENTATION_TIERS[assessment['tier']]
        st.metric("Current Tier", f"{tier_info['name']} ({assessment['tier']})")
        st.metric("Confidence", f"{assessment['confidence']:.1%}")

        st.write("**Description:**", tier_info['description'])
        st.write("**Characteristics:**")
        for char in tier_info['characteristics']:
            st.write(f"- {char}")

    st.subheader("Detailed Analysis")
    for func in NIST_FUNCTIONS.keys():
        with st.expander(f"{func.capitalize()} Analysis", expanded=(func=='identify')):
            if func in assessment['analysis']:
                an = assessment['analysis'][func]
                sc_col, w_col = st.columns(2)
                with sc_col:
                    st.metric("Score", f"{an['score']:.2f}")
                with w_col:
                    st.metric("Weight", f"{an['weight']:.1f}")
                st.write("**Categories:**")
                for cat in an['categories']:
                    st.write(f"- {cat}")

    st.subheader("Recommendations")
    recs = sorted(
        assessment['recommendations'],
        key=lambda x: (
            0 if x.startswith("Critical") else
            1 if x.startswith("High") else
            2 if x.startswith("Medium") else 3
        )
    )
    for r in recs:
        st.info(r)


# ---------------------------------------------------------------------
# 6) STREAMLIT UI - ATTACK SIMULATION
# ---------------------------------------------------------------------
def show_simulation_section():
    st.header("Attack Impact Simulation")
    if 'latest_assessment' not in st.session_state:
        st.warning("Please complete an assessment first.")
        return
    
    attack_type = st.selectbox("Select Attack Scenario", list(ATTACK_SCENARIOS.keys()))
    st.info(ATTACK_SCENARIOS[attack_type]['description'])

    with st.expander("Attack Progression"):
        for i,stage in enumerate(ATTACK_SCENARIOS[attack_type]['progression_stages'],1):
            st.write(f"{i}. {stage}")

    if st.button("Run Simulation"):
        with st.spinner("Simulating..."):
            latest = st.session_state['latest_assessment']
            result = simulate_attack(latest['scores'], attack_type)
            show_simulation_results(result)

def show_simulation_results(result: Dict):
    st.subheader("Impact Analysis")
    col1,col2 = st.columns(2)
    with col1:
        st.subheader("Before Attack")
        fig1 = go.Figure(data=go.Scatterpolar(
            r=list(result['original_scores'].values()),
            theta=[f.capitalize() for f in result['original_scores'].keys()],
            fill='toself'
        ))
        fig1.update_layout(polar={'radialaxis':{'range':[0,4]}}, title="Scores Before Attack")
        st.plotly_chart(fig1)

    with col2:
        st.subheader("After Attack")
        fig2 = go.Figure(data=go.Scatterpolar(
            r=list(result['post_attack_scores'].values()),
            theta=[f.capitalize() for f in result['post_attack_scores'].keys()],
            fill='toself'
        ))
        fig2.update_layout(polar={'radialaxis':{'range':[0,4]}}, title="Scores After Attack")
        st.plotly_chart(fig2)

    st.subheader("Detailed Impact Analysis")
    df = pd.DataFrame({
        'Function': [f.capitalize() for f in result['original_scores'].keys()],
        'Before': list(result['original_scores'].values()),
        'Impact': list(result['impact'].values()),
        'After': list(result['post_attack_scores'].values())
    })
    styler = df.style.applymap(
        lambda val: 'background-color: #FFA07A' if isinstance(val,(int,float)) and val<0 else '',
        subset=['Impact']
    )
    st.dataframe(styler)

    # Post-Attack Assessment
    if 'model' in st.session_state:
        st.subheader("Post-Attack Assessment")
        with st.spinner("Analyzing post-attack state..."):
            # ใส่ default หากไม่มี vulnerabilities/security_metrics
            def_vulns = {'Critical':0,'High':0,'Medium':0,'Low':0,'Info':0}
            def_metrics = {
                'identify':{'controls':0,'findings':0},
                'protect':{'controls':0,'findings':0},
                'detect':{'controls':0,'findings':0},
                'respond':{'controls':0,'findings':0},
                'recover':{'controls':0,'findings':0},
                'govern':{'controls':0,'findings':0}
            }
            latest = st.session_state['latest_assessment']
            post_pred = st.session_state['model'].predict({
                'scores': result['post_attack_scores'],
                'vulnerabilities': latest.get('vulnerabilities', def_vulns),
                'security_metrics': latest.get('security_metrics', def_metrics)
            })
            if post_pred['status'] == 'success':
                st.write("**New Implementation Tier:**", post_pred['tier'])
                st.write("**Recommendations for Recovery:**")
                for rec in post_pred['recommendations']:
                    st.write(f"- {rec}")


# ---------------------------------------------------------------------
# 7) STREAMLIT UI - HISTORY
# ---------------------------------------------------------------------
def show_history_section():
    st.header("Assessment History")
    if 'model' not in st.session_state:
        st.session_state['model'] = NISTAssessmentModel()

    hist = st.session_state['model'].history
    if not hist:
        st.warning("No assessment history available.")
        return

    st.subheader("Assessment Statistics")
    c1,c2,c3 = st.columns(3)
    with c1:
        st.metric("Total Assessments", len(hist))
    with c2:
        tiers = [h['tier'] for h in hist]
        st.metric("Most Common Tier", max(set(tiers), key=tiers.count))
    with c3:
        avg_score = np.mean([sum(h['scores'].values())/len(h['scores']) for h in hist])
        st.metric("Average Score", f"{avg_score:.2f}")

    st.subheader("Score Trends")
    trend_data=[]
    for h in hist:
        for func, sc in h['scores'].items():
            trend_data.append({
                'Date': pd.to_datetime(h['timestamp']),
                'Function': func.capitalize(),
                'Score': sc
            })
    df= pd.DataFrame(trend_data)
    fig = px.line(df, x='Date', y='Score', color='Function', title='Score Trends Over Time')
    fig.update_layout(yaxis_range=[1,4])
    st.plotly_chart(fig)

    st.subheader("Detailed History")
    hdf = pd.DataFrame([
        {
            'Date': h['timestamp'],
            'Tier': h['tier'],
            'Confidence': f"{h['confidence']:.1%}",
            'Average Score': sum(h['scores'].values())/len(h['scores']),
            **{f"{k.capitalize()} Score": v for k,v in h['scores'].items()}
        }
        for h in hist
    ])
    st.dataframe(hdf.sort_values('Date', ascending=False))


# ---------------------------------------------------------------------
# 8) MAIN APPLICATION
# ---------------------------------------------------------------------
def main():
    st.title("NIST CSF 2.0 Cybersecurity Assessment System (Pre-Trained Model)")
    st.markdown("""
        This system provides AI-powered cybersecurity assessment using the NIST CSF 2.0 framework.
        It also simulates different cyberattack scenarios with distinct impacts.

        **Note**: The model is already pre-trained (model.pkl). 
        Users only need to upload .nessus files to perform an assessment.
    """)

    # โหลดโมเดลไว้ก่อน (ถ้ายังไม่มีใน session state)
    if 'model' not in st.session_state:
        st.session_state['model'] = NISTAssessmentModel()
        st.session_state['model'].load_model()

    total_assess = len(st.session_state['model'].history) if hasattr(st.session_state['model'],'history') else 0
    c1,c2,c3 = st.columns(3)
    with c1:
        st.metric("Total Assessments", total_assess)
    with c2:
        st.metric("Model Iterations", st.session_state['model'].iterations)
    with c3:
        st.metric("Last Updated", datetime.now().strftime("%Y-%m-%d"))

    # แสดงเฉพาะ 3 เมนู: Assessment / Attack Simulation / History
    menu = ["Assessment", "Attack Simulation", "History"]
    choice = st.sidebar.selectbox("Select Function", menu)

    if choice == "Assessment":
        show_assessment_section()
    elif choice == "Attack Simulation":
        show_simulation_section()
    elif choice == "History":
        show_history_section()

if __name__=="__main__":
    main()

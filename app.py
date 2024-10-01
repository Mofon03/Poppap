import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import random

# ฟังก์ชันสำหรับสร้างข้อมูลจำลอง
def generate_sample_data(n_samples=1000):
    np.random.seed(42)
    data = pd.DataFrame({
        'identify': np.random.randint(0, 5, n_samples),
        'protect': np.random.randint(0, 5, n_samples),
        'detect': np.random.randint(0, 5, n_samples),
        'respond': np.random.randint(0, 5, n_samples),
        'recover': np.random.randint(0, 5, n_samples),
        'govern': np.random.randint(0, 5, n_samples),
        'vulnerabilities': np.random.randint(0, 100, n_samples),
        'incidents': np.random.randint(0, 50, n_samples),
    })
    data['risk_level'] = pd.cut(data['vulnerabilities'] + data['incidents'], 
                                bins=[0, 30, 60, 150], 
                                labels=['Low', 'Medium', 'High'])
    return data

# ฟังก์ชันสำหรับฝึกโมเดล AI
@st.cache_resource
def train_ai_model():
    data = generate_sample_data()
    X = data.drop('risk_level', axis=1)
    y = data['risk_level']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    return model, scaler

# ฟังก์ชันสำหรับทำนายความเสี่ยง
def predict_risk(model, scaler, metrics):
    input_data = np.array([[metrics['identify'], metrics['protect'], metrics['detect'],
                            metrics['respond'], metrics['recover'], metrics['govern'],
                            metrics['vulnerabilities'], metrics['incidents']]])
    input_scaled = scaler.transform(input_data)
    prediction = model.predict(input_scaled)[0]
    probabilities = model.predict_proba(input_scaled)[0]
    return prediction, probabilities

# ฟังก์ชันสำหรับให้คำแนะนำ
def get_ai_recommendations(metrics, prediction):
    recommendations = {
        'Low': [
            "Increase cybersecurity awareness training for all employees.",
            "Implement basic access controls and authentication mechanisms.",
            "Develop an incident response plan."
        ],
        'Medium': [
            "Enhance network segmentation to limit potential breach impacts.",
            "Implement advanced threat detection systems.",
            "Regularly conduct vulnerability assessments and penetration testing."
        ],
        'High': [
            "Implement a comprehensive Security Information and Event Management (SIEM) solution.",
            "Develop a rigorous third-party risk management program.",
            "Implement a zero-trust architecture across the organization."
        ]
    }
    base_recommendations = recommendations[prediction]
    
    # AI-enhanced recommendations
    if metrics['identify'] < 2:
        base_recommendations.append("Prioritize improving asset management and risk assessment processes.")
    if metrics['protect'] < 2:
        base_recommendations.append("Focus on enhancing data protection measures and access control mechanisms.")
    if metrics['detect'] < 2:
        base_recommendations.append("Invest in advanced threat detection and continuous monitoring capabilities.")
    
    return base_recommendations[:3]  # Return top 3 recommendations

# ฟังก์ชันสำหรับจำลองการโจมตี
def simulate_attack(attack_type, severity, metrics):
    impact = {
        'identify': max(-1, random.uniform(-0.5, 0) * severity),
        'protect': max(-1, random.uniform(-0.5, 0) * severity),
        'detect': max(-1, random.uniform(-0.5, 0) * severity),
        'respond': max(-1, random.uniform(-0.5, 0) * severity),
        'recover': max(-1, random.uniform(-0.5, 0) * severity),
        'govern': max(-1, random.uniform(-0.5, 0) * severity),
        'vulnerabilities': random.randint(5, 20) * severity,
        'incidents': random.randint(1, 5) * severity
    }
    
    new_metrics = {key: max(0, min(4, metrics[key] + impact[key])) for key in metrics if key not in ['vulnerabilities', 'incidents']}
    new_metrics['vulnerabilities'] = min(100, metrics['vulnerabilities'] + impact['vulnerabilities'])
    new_metrics['incidents'] = min(50, metrics['incidents'] + impact['incidents'])
    
    attack_description = {
        'DDoS': "Distributed Denial of Service attack overwhelmed the network.",
        'Phishing': "Phishing campaign targeted employees, potentially compromising credentials.",
        'Malware': "Malware infection detected in several systems, risking data integrity."
    }
    
    return new_metrics, attack_description[attack_type]

# ฟังก์ชันสำหรับแสดงผลการประเมิน
def display_assessment(metrics, org_name, org_size, industry):
    prediction, probabilities = predict_risk(model, scaler, metrics)
    
    st.subheader(f'AI-based Risk Assessment Result for {org_name}')
    st.write(f'Organization Size: {org_size}')
    st.write(f'Industry: {industry}')
    st.write(f'Predicted Risk Level: {prediction}')
    
    # สร้าง bar chart สำหรับความมั่นใจ
    fig = go.Figure(go.Bar(
        x=[prediction],
        y=[probabilities[list(model.classes_).index(prediction)] * 100],
        text=f"{probabilities[list(model.classes_).index(prediction)] * 100:.2f}%",
        textposition='auto',
        marker=dict(color='lightskyblue'),
        name='Confidence'
    ))
    fig.update_layout(
        title=f"Risk Prediction and Confidence for {org_name}",
        xaxis_title="Predicted Risk Level",
        yaxis_title="Confidence (%)",
        yaxis_range=[0, 100]
    )
    st.plotly_chart(fig)
    
    # สร้าง radar chart สำหรับแสดง capability ของแต่ละฟังก์ชัน
    categories = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover', 'Govern']
    values = [metrics['identify'], metrics['protect'], metrics['detect'],
              metrics['respond'], metrics['recover'], metrics['govern']]
    
    radar_fig = go.Figure(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        name='Cybersecurity Capabilities'
    ))
    
    radar_fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 4]
            )
        ),
        title=f"Cybersecurity Capabilities for {org_name}",
        showlegend=False
    )
    st.plotly_chart(radar_fig)
    
    # AI-generated recommendations
    recommendations = get_ai_recommendations(metrics, prediction)
    st.subheader('Top 3 AI-generated Recommendations:')
    for i, rec in enumerate(recommendations, 1):
        st.write(f"{i}. {rec}")

# สร้าง Streamlit UI
st.title('AI-powered Cybersecurity Assessment System using NIST CSF 2.0')

# โหลดโมเดล AI
model, scaler = train_ai_model()

# ส่วนกรอกข้อมูลองค์กร
st.header('Organization Information')
org_name = st.text_input('Organization Name')
org_size = st.selectbox('Organization Size', ['Small', 'Medium', 'Large'])
industry = st.selectbox('Industry', ['Finance', 'Healthcare', 'Technology', 'Retail', 'Manufacturing', 'Government', 'Other'])

# สร้างฟอร์มสำหรับกรอกข้อมูล NIST CSF
st.header('Enter Cybersecurity Metrics')

metrics = {}
for func in ['Identify', 'Protect', 'Detect', 'Respond', 'Recover', 'Govern']:
    metrics[func.lower()] = st.slider(f'{func} Capability', min_value=0, max_value=4, value=2)

metrics['vulnerabilities'] = st.number_input('Number of Known Vulnerabilities', 0, 100, 50)
metrics['incidents'] = st.number_input('Number of Security Incidents in the Last Year', 0, 50, 10)

# ประเมินความเสี่ยง
if st.button('Assess Cybersecurity Posture'):
    if not org_name:
        st.error('Please enter the Organization Name before assessment.')
    else:
        display_assessment(metrics, org_name, org_size, industry)

# ส่วนจำลองการโจมตี
st.header("Cyber Attack Simulation")
attack_type = st.selectbox("Select Attack Type", ["DDoS", "Phishing", "Malware"])
severity = st.slider("Attack Severity", 1, 5, 3)

if st.button("Simulate Attack"):
    new_metrics, attack_desc = simulate_attack(attack_type, severity, metrics)
    
    st.subheader("Attack Simulation Results")
    st.write(f"Attack Type: {attack_type}")
    st.write(f"Attack Description: {attack_desc}")
    st.write("Impact on Cybersecurity Metrics:")
    for func in metrics:
        change = new_metrics[func] - metrics[func]
        st.write(f"{func.capitalize()}: {metrics[func]:.2f} -> {new_metrics[func]:.2f} (Change: {change:.2f})")
    
    st.subheader("New Assessment After Attack")
    display_assessment(new_metrics, org_name, org_size, industry)

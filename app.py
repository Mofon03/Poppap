import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import plotly.graph_objects as go

# ฟังก์ชันสำหรับสร้างโมเดล
@st.cache_resource
def create_model():
    data = pd.DataFrame({
        'security_level': ['Low', 'Medium', 'High'] * 100,
        'identify': np.random.randint(1, 6, 300),
        'protect': np.random.randint(1, 6, 300),
        'detect': np.random.randint(1, 6, 300),
        'respond': np.random.randint(1, 6, 300),
        'recover': np.random.randint(1, 6, 300),
        'govern': np.random.randint(1, 6, 300),
        'vulnerabilities': np.random.randint(0, 100, 300),
        'incidents': np.random.randint(0, 50, 300)
    })
    
    le = LabelEncoder()
    data['security_level'] = le.fit_transform(data['security_level'])
    
    X = data.drop('security_level', axis=1)
    y = data['security_level']
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    return model, le

# ฟังก์ชันสำหรับจำลองการโจมตี
def simulate_attack(attack_type, severity):
    impact = {
        'identify': max(-1, -np.random.randint(0, 2)),
        'protect': max(-1, -np.random.randint(0, 2)),
        'detect': max(-1, -np.random.randint(0, 2)),
        'respond': max(-1, -np.random.randint(0, 2)),
        'recover': max(-1, -np.random.randint(0, 2)),
        'govern': max(-1, -np.random.randint(0, 2)),
        'vulnerabilities': np.random.randint(5, 20) * severity,
        'incidents': np.random.randint(1, 5) * severity
    }
    return impact

# สร้างโมเดลและโหลดข้อมูลที่จำเป็น
model, le = create_model()

# สร้าง Streamlit UI
st.title('AI-based Cybersecurity Assessment System using NIST CSF 2.0')

# สร้างฟอร์มสำหรับกรอกข้อมูล
st.header('Enter Cybersecurity Metrics')

col1, col2 = st.columns(2)

with col1:
    identify = st.slider('Identify Maturity', 1, 5, 3)
    protect = st.slider('Protect Maturity', 1, 5, 3)
    detect = st.slider('Detect Maturity', 1, 5, 3)

with col2:
    respond = st.slider('Respond Maturity', 1, 5, 3)
    recover = st.slider('Recover Maturity', 1, 5, 3)
    govern = st.slider('Govern Maturity', 1, 5, 3)

vulnerabilities = st.number_input('Number of Vulnerabilities', 0, 100, 50)
incidents = st.number_input('Number of Security Incidents', 0, 50, 10)

# ประเมินความเสี่ยง
if st.button('Assess Cybersecurity Posture'):
    input_data = pd.DataFrame({
        'identify': [identify],
        'protect': [protect],
        'detect': [detect],
        'respond': [respond],
        'recover': [recover],
        'govern': [govern],
        'vulnerabilities': [vulnerabilities],
        'incidents': [incidents]
    })
    
    prediction = model.predict(input_data)
    prediction_proba = model.predict_proba(input_data)
    
    st.subheader('Risk Assessment Result:')
    st.write(f'Predicted Security Level: {le.inverse_transform(prediction)[0]}')
    
    fig = go.Figure(data=[go.Bar(x=le.classes_, y=prediction_proba[0])])
    fig.update_layout(title='Probability of Each Security Level', xaxis_title='Security Level', yaxis_title='Probability')
    st.plotly_chart(fig)

# จำลองการโจมตี
st.header("Cyber Attack Simulation")

attack_type = st.selectbox("Select Attack Type", ["DDoS", "Phishing", "Malware"])
severity = st.slider("Attack Severity", 1, 5, 3)

if st.button("Simulate Attack"):
    impact = simulate_attack(attack_type, severity)
    
    st.subheader("Attack Impact:")
    for key, value in impact.items():
        st.write(f"{key.capitalize()}: {value}")
    
    # ปรับปรุงค่าตามผลกระทบ
    new_input_data = pd.DataFrame({
        'identify': [max(1, identify + impact['identify'])],
        'protect': [max(1, protect + impact['protect'])],
        'detect': [max(1, detect + impact['detect'])],
        'respond': [max(1, respond + impact['respond'])],
        'recover': [max(1, recover + impact['recover'])],
        'govern': [max(1, govern + impact['govern'])],
        'vulnerabilities': [vulnerabilities + impact['vulnerabilities']],
        'incidents': [incidents + impact['incidents']]
    })
    
    new_prediction = model.predict(new_input_data)
    new_prediction_proba = model.predict_proba(new_input_data)
    
    st.subheader('New Risk Assessment After Attack:')
    st.write(f'New Predicted Security Level: {le.inverse_transform(new_prediction)[0]}')
    
    new_fig = go.Figure(data=[go.Bar(x=le.classes_, y=new_prediction_proba[0])])
    new_fig.update_layout(title='New Probability of Each Security Level After Attack', xaxis_title='Security Level', yaxis_title='Probability')
    st.plotly_chart(new_fig)

st.sidebar.info('This is a demo of an AI-based Cybersecurity Assessment System using NIST Cybersecurity Framework 2.0.')
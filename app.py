import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import random

# ฟังก์ชันสำหรับคำนวณคะแนน NIST CSF
def calculate_nist_score(metrics):
    weights = {
        'identify': 0.2, 'protect': 0.2, 'detect': 0.2,
        'respond': 0.15, 'recover': 0.15, 'govern': 0.1
    }
    return sum(metrics[func] * weight for func, weight in weights.items()) * 20

# ฟังก์ชันสำหรับให้คำแนะนำ
def get_recommendations(security_level):
    recommendations = {
        'Low': [
            "Improve asset management and risk assessment processes.",
            "Enhance access control and implement regular security awareness training.",
            "Implement continuous monitoring and improve anomaly detection capabilities."
        ],
        'Medium': [
            "Refine risk assessment methodologies and update asset inventory regularly.",
            "Strengthen data protection measures and enhance network segmentation.",
            "Improve threat intelligence capabilities and implement advanced security analytics."
        ],
        'High': [
            "Implement advanced risk modeling and expand supply chain risk management.",
            "Adopt zero trust architecture and implement advanced encryption techniques.",
            "Implement AI-driven threat detection and expand threat hunting capabilities."
        ]
    }
    return recommendations[security_level]

# ฟังก์ชันจำลองการโจมตี
def simulate_attack(attack_type, severity, metrics):
    impact = {
        'identify': random.uniform(0, -0.5) * severity,
        'protect': random.uniform(0, -0.5) * severity,
        'detect': random.uniform(0, -0.5) * severity,
        'respond': random.uniform(0, -0.5) * severity,
        'recover': random.uniform(0, -0.5) * severity,
        'govern': random.uniform(0, -0.5) * severity
    }
    
    new_metrics = {key: max(1, value + impact[key]) for key, value in metrics.items()}
    
    attack_description = {
        'DDoS': "Distributed Denial of Service attack overwhelmed the network.",
        'Phishing': "Phishing campaign targeted employees, potentially compromising credentials.",
        'Malware': "Malware infection detected in several systems, risking data integrity."
    }
    
    return new_metrics, attack_description[attack_type]

# สร้าง Streamlit UI
st.title('Cybersecurity Assessment System using NIST CSF 2.0')

# ส่วนกรอกข้อมูลองค์กร
st.header('Organization Information')
org_name = st.text_input('Organization Name')
org_size = st.selectbox('Organization Size', ['Small', 'Medium', 'Large'])
industry = st.selectbox('Industry', ['Finance', 'Healthcare', 'Technology', 'Retail', 'Manufacturing', 'Government', 'Other'])

# สร้างฟอร์มสำหรับกรอกข้อมูล NIST CSF
st.header('Enter Cybersecurity Metrics')

metrics = {}
for func in ['Identify', 'Protect', 'Detect', 'Respond', 'Recover', 'Govern']:
    metrics[func.lower()] = st.slider(f'{func} Maturity', 1, 5, 3)

# ฟังก์ชันสำหรับแสดงผลการประเมิน
def display_assessment(metrics, org_name, org_size, industry):
    nist_score = calculate_nist_score(metrics)
    
    if nist_score < 60:
        security_level = 'Low'
    elif nist_score < 80:
        security_level = 'Medium'
    else:
        security_level = 'High'
    
    st.subheader(f'Risk Assessment Result for {org_name}')
    st.write(f'Organization Size: {org_size}')
    st.write(f'Industry: {industry}')
    st.write(f'NIST CSF Score: {nist_score:.2f}%')
    st.write(f'Security Level: {security_level}')
    
    # สร้าง gauge chart
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = nist_score,
        title = {'text': "NIST CSF Score"},
        gauge = {
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 60], 'color': "red"},
                {'range': [60, 80], 'color': "yellow"},
                {'range': [80, 100], 'color': "green"}
            ]
        }
    ))
    st.plotly_chart(fig)
    
    # ให้คำแนะนำ
    recommendations = get_recommendations(security_level)
    st.subheader('Top 3 Recommendations:')
    for i, rec in enumerate(recommendations, 1):
        st.write(f"{i}. {rec}")
    
    # แสดงรายละเอียดของแต่ละฟังก์ชัน NIST CSF
    st.subheader('NIST CSF Function Details:')
    for func, value in metrics.items():
        st.write(f"{func.capitalize()}: {value:.2f}/5")
        st.progress(value/5)

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

st.sidebar.info('This is a demo of a Cybersecurity Assessment System using NIST Cybersecurity Framework 2.0 with attack simulation.')

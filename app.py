import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# ปิดการแจ้งเตือนเกี่ยวกับ SSL verification
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ฟังก์ชันสำหรับทดสอบการเชื่อมต่อ Nessus
def test_nessus_connection(url, access_key, secret_key):
    headers = {
        'X-ApiKeys': f'accessKey={access_key};secretKey={secret_key}',
        'Content-Type': 'application/json',
    }
    try:
        response = requests.get(f'{url}/server/status', headers=headers, verify=False)
        response.raise_for_status()
        return True, "Connection successful! API is accessible."
    except requests.exceptions.RequestException as e:
        return False, f"Connection failed: {str(e)}"

# ฟังก์ชันสำหรับดึงข้อมูลจาก Nessus
def get_nessus_data(url, access_key, secret_key, scan_id):
    headers = {
        'X-ApiKeys': f'accessKey={access_key};secretKey={secret_key}',
        'Content-Type': 'application/json',
    }
    try:
        response = requests.get(f'{url}/scans/{scan_id}', headers=headers, verify=False)
        response.raise_for_status()
        scan_details = response.json()
        
        vulnerabilities = {
            'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0
        }
        
        hosts_data = []
        for host in scan_details.get('hosts', []):
            for severity in vulnerabilities.keys():
                vulnerabilities[severity] += host.get(severity.lower(), 0)
            
            hosts_data.append({
                'Host': host.get('hostname', 'Unknown'),
                'Critical': host.get('critical', 0),
                'High': host.get('high', 0),
                'Medium': host.get('medium', 0),
                'Low': host.get('low', 0),
                'Info': host.get('info', 0)
            })
        
        return vulnerabilities, hosts_data
    except requests.exceptions.RequestException as e:
        return None, f"Error fetching Nessus data: {str(e)}"

# ฟังก์ชันสำหรับสร้างและฝึกโมเดล AI
@st.cache_resource
def create_model():
    data = pd.DataFrame({
        'identify': np.random.randint(1, 5, 1000),
        'protect': np.random.randint(1, 5, 1000),
        'detect': np.random.randint(1, 5, 1000),
        'respond': np.random.randint(1, 5, 1000),
        'recover': np.random.randint(1, 5, 1000),
        'govern': np.random.randint(1, 5, 1000),
        'vulnerabilities': np.random.randint(0, 1000, 1000),
        'risk_level': np.random.choice(['Low', 'Medium', 'High'], 1000)
    })
    
    X = data.drop('risk_level', axis=1)
    y = data['risk_level']
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)
    
    return model, scaler

# ฟังก์ชันสำหรับจำลองการโจมตี
def simulate_attack(attack_type, current_metrics):
    impact = {
        'identify': np.random.randint(-1, 1),
        'protect': np.random.randint(-2, 0),
        'detect': np.random.randint(-1, 2),
        'respond': np.random.randint(-1, 2),
        'recover': np.random.randint(-1, 1),
        'govern': 0,
        'vulnerabilities': np.random.randint(5, 50)
    }
    
    for key in impact:
        if key != 'vulnerabilities':
            current_metrics[key] = max(1, min(current_metrics[key] + impact[key], 4))
        else:
            current_metrics[key] += impact[key]
    
    return current_metrics, impact

# สร้าง Streamlit app
st.set_page_config(page_title="Cybersecurity Risk Assessment", layout="wide")
st.title('AI-powered Cybersecurity Risk Assessment System using NIST CSF 2.0')

# สร้าง sidebar สำหรับการนำทาง
page = st.sidebar.radio("Navigate", ["Nessus Connection", "Organization Info", "Data Input", "Risk Assessment", "Attack Simulation"])

# โหลดโมเดล
model, scaler = create_model()

if page == "Nessus Connection":
    st.header("Nessus Connection")
    
    nessus_url = st.text_input("Nessus URL", value="https://localhost:8834")
    access_key = st.text_input("Access Key", value="your_access_key_here")
    secret_key = st.text_input("Secret Key", value="your_secret_key_here", type="password")
    scan_id = st.number_input("Scan ID", min_value=1, value=37)

    if st.button("Test Nessus Connection"):
        success, message = test_nessus_connection(nessus_url, access_key, secret_key)
        if success:
            st.success(message)
        else:
            st.error(message)

    if st.button("Fetch Nessus Data"):
        vulnerabilities, hosts_data = get_nessus_data(nessus_url, access_key, secret_key, scan_id)
        if vulnerabilities:
            st.success("Data fetched successfully!")
            st.session_state['vulnerabilities'] = vulnerabilities
            st.session_state['hosts_data'] = hosts_data
            
            st.subheader("Vulnerabilities Summary")
            col1, col2 = st.columns(2)
            with col1:
                for severity, count in vulnerabilities.items():
                    if severity != 'Info':
                        st.metric(label=severity, value=count)
            with col2:
                fig = go.Figure(data=[go.Pie(labels=list(vulnerabilities.keys()), 
                                             values=list(vulnerabilities.values()),
                                             hole=.3)])
                fig.update_layout(title="Vulnerability Distribution")
                st.plotly_chart(fig)
            
            st.subheader("Host Data")
            st.dataframe(pd.DataFrame(hosts_data))
        else:
            st.error(hosts_data)

elif page == "Organization Info":
    st.header("Organization Information")
    
    org_name = st.text_input("Organization Name")
    org_size = st.selectbox("Organization Size", ["Small", "Medium", "Large"])
    industry = st.selectbox("Industry", ["Finance", "Healthcare", "Technology", "Retail", "Manufacturing", "Other"])
    
    contact_name = st.text_input("Contact Person Name")
    contact_email = st.text_input("Contact Email")
    
    if st.button("Save Organization Info"):
        st.session_state['org_info'] = {
            'name': org_name,
            'size': org_size,
            'industry': industry,
            'contact_name': contact_name,
            'contact_email': contact_email
        }
        st.success("Organization information saved successfully!")

elif page == "Data Input":
    st.header("Data Input")
    
    if 'org_info' not in st.session_state:
        st.warning("Please fill in the Organization Information first.")
    else:
        st.subheader("NIST CSF 2.0 Capabilities")
        metrics = {}
        for metric in ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']:
            metrics[metric] = st.slider(f"{metric.capitalize()} Capability", 1, 4, 2)
        
        st.subheader("Vulnerability Data")
        if 'vulnerabilities' in st.session_state:
            vulnerabilities = st.session_state['vulnerabilities']
            total_vulns = sum(vulnerabilities[severity] for severity in ['Critical', 'High', 'Medium', 'Low'])
            st.write(f"Total vulnerabilities detected: {total_vulns}")
            metrics['vulnerabilities'] = st.number_input("Confirm or adjust number of vulnerabilities", 0, 1000, total_vulns)
        else:
            metrics['vulnerabilities'] = st.number_input("Number of Vulnerabilities", 0, 1000, 50)
        
        if st.button("Save Data"):
            st.session_state['metrics'] = metrics
            st.success("Data saved successfully!")

elif page == "Risk Assessment":
    st.header("Risk Assessment")
    
    if 'metrics' not in st.session_state:
        st.error("Please input data in the Data Input page first.")
    else:
        metrics = st.session_state['metrics']
        
        input_data = np.array([[metrics[key] for key in metrics]])
        input_scaled = scaler.transform(input_data)
        risk_level = model.predict(input_scaled)[0]
        risk_proba = model.predict_proba(input_scaled)[0]
        
        st.subheader("Current Risk Assessment")
        st.write(f"Predicted Risk Level: {risk_level}")
        
        fig = go.Figure(data=[go.Bar(x=['Low', 'Medium', 'High'], y=risk_proba)])
        fig.update_layout(title="Risk Level Probabilities", xaxis_title="Risk Level", yaxis_title="Probability")
        st.plotly_chart(fig)

elif page == "Attack Simulation":
    st.header("Attack Simulation")
    
    if 'metrics' not in st.session_state:
        st.error("Please complete the Risk Assessment first.")
    else:
        metrics = st.session_state['metrics'].copy()
        
        st.subheader("Simulation Controls")
        attack_type = st.selectbox("Select Attack Type", ["malware", "phishing", "ddos", "data_breach"])
        
        if st.button("Run Simulation"):
            new_metrics, impact = simulate_attack(attack_type, metrics)
            
            st.subheader("Simulation Results")
            st.write("Impact of the attack:")
            for key, value in impact.items():
                st.write(f"- {key}: {value}")
            
            input_data = np.array([[new_metrics[key] for key in new_metrics]])
            input_scaled = scaler.transform(input_data)
            new_risk_level = model.predict(input_scaled)[0]
            new_risk_proba = model.predict_proba(input_scaled)[0]
            
            st.subheader("Post-Attack Risk Assessment")
            st.write(f"New Predicted Risk Level: {new_risk_level}")
            
            fig = go.Figure(data=[
                go.Bar(name='Before Attack', x=['Low', 'Medium', 'High'], y=model.predict_proba(scaler.transform(np.array([[metrics[key] for key in metrics]])))[0]),
                go.Bar(name='After Attack', x=['Low', 'Medium', 'High'], y=new_risk_proba)
            ])
            fig.update_layout(title="Risk Level Probabilities Comparison", xaxis_title="Risk Level", yaxis_title="Probability", barmode='group')
            st.plotly_chart(fig)

            st.session_state['metrics'] = new_metrics
            st.success("Metrics updated after the attack simulation.")

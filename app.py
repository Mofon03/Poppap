import requests
import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Set page configuration; must be the first command
st.set_page_config(page_title="Cybersecurity Risk Assessment", layout="wide")

# Disable SSL verification warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Function to save and load models
def save_model(model, filename):
    joblib.dump(model, filename)

def load_model(filename):
    return joblib.load(filename)

# Function to save data to JSON file
def save_data_to_json(data, filename='nessus_data.json'):
    with open(filename, 'w') as f:
        json.dump(data, f)

# Function to load data from JSON file
def load_data_from_json(filename='nessus_data.json'):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
        return data
    return None

# Function to test Nessus connection
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

# Function to fetch data from Nessus
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

# Function to create and train the AI model
@st.cache_resource
def create_model(vulnerabilities_data):
    if not isinstance(vulnerabilities_data, list):
        st.error("vulnerabilities_data is not in the expected format. It should be a list of dictionaries.")
        return None, None

    if not all(isinstance(item, dict) for item in vulnerabilities_data):
        st.error("Each item in vulnerabilities_data should be a dictionary.")
        return None, None

    try:
        data = pd.DataFrame(vulnerabilities_data)
    except Exception as e:
        st.error(f"Error converting to DataFrame: {e}")
        return None, None

    # Add simulated features for NIST CSF 2.0
    n_samples = len(vulnerabilities_data)
    for feature in ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']:
        if feature not in data.columns:
            data[feature] = np.random.randint(1, 5, n_samples)

    data['risk_level'] = pd.cut(data['Critical'] + data['High'] + data['Medium'],
                                bins=[0, 10, 30, float('inf')],
                                labels=['Low', 'Medium', 'High'])

    for column in data.columns:
        if data[column].dtype.name == 'category':
            data[column] = data[column].cat.add_categories(['Unknown']).fillna('Unknown')
        else:
            data[column].fillna(0, inplace=True)

    X = data[['identify', 'protect', 'detect', 'respond', 'recover', 'govern',
              'Critical', 'High', 'Medium', 'Low', 'Info']]
    y = data['risk_level']

    if X.isnull().any().any() or y.isnull().any():
        raise ValueError("Input contains NaN after handling missing values")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model_filename = 'risk_assessment_model.joblib'
    if os.path.exists(model_filename):
        model = load_model(model_filename)
        st.info("Loaded existing model")
    else:
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_scaled, y)
        save_model(model, model_filename)
        st.info("Created and saved new model")

    return model, scaler

# Function to simulate an attack
def simulate_attack(attack_type, current_metrics):
    impact = {
        'identify': np.random.randint(-1, 1),
        'protect': np.random.randint(-2, 0),
        'detect': np.random.randint(-1, 2),
        'respond': np.random.randint(-1, 2),
        'recover': np.random.randint(-1, 1),
        'govern': 0,
        'Critical': np.random.randint(1, 5),
        'High': np.random.randint(1, 5),
        'Medium': np.random.randint(1, 5),
        'Low': np.random.randint(0, 3),
        'Info': np.random.randint(0, 3)
    }

    for key in impact:
        if key in current_metrics:
            current_metrics[key] = max(0, current_metrics[key] + impact[key])

    return current_metrics, impact

# Build the Streamlit app
st.title('AI-powered Cybersecurity Risk Assessment System using NIST ๅๅCSF 2.0')

# Create sidebar for navigation
page = st.sidebar.radio("Navigate", ["Nessus Connection", "Organization Info", "Data Input", "Risk Assessment", "Attack Simulation"])

# Nessus Connection section
if page == "Nessus Connection":
    st.header("Nessus Connection")

    nessus_url = st.text_input("Nessus URL", value="https://localhost:8834")
    access_key = st.text_input("Access Key", value="your_access_key_here")
    secret_key = st.text_input("Secret Key", value="your_secret_key_here", type="password")
    scan_id = st.number_input("Scan ID", min_value=1, value=37)

    show_data = False  # Initialize show_data

    saved_data = load_data_from_json()
    if saved_data is not None:
        if 'nessus_data' not in st.session_state:
            st.session_state['nessus_data'] = saved_data

        if st.button("Use Existing Data"):
            vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
            hosts_data = st.session_state['nessus_data']['hosts_data']
            st.success("Loaded data from JSON file")
            st.write("Current hosts_data:", hosts_data)
            show_data = True

            # Create and store the model and scaler using existing data
            model, scaler = create_model(hosts_data)
            if model and scaler:
                st.session_state['model'] = model
                st.session_state['scaler'] = scaler
                st.success("Model created and stored in session state.")
            else:
                st.error("Failed to create model from existing data.")

    if st.button("Test Nessus Connection"):
        success, message = test_nessus_connection(nessus_url, access_key, secret_key)
        if success:
            st.success(message)
        else:
            st.error(message)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Fetch New Nessus Data"):
            vulnerabilities, hosts_data = get_nessus_data(nessus_url, access_key, secret_key, scan_id)
            if isinstance(vulnerabilities, dict):
                st.session_state['nessus_data'] = {'vulnerabilities': vulnerabilities, 'hosts_data': hosts_data}
                save_data_to_json(st.session_state['nessus_data'])
                st.success("Fetched and saved new Nessus data")
                st.write("Current hosts_data:", hosts_data)
                show_data = True

                # Create and store the model and scaler
                model, scaler = create_model(hosts_data)
                if model and scaler:
                    st.session_state['model'] = model
                    st.session_state['scaler'] = scaler
                    st.success("Model created and stored in session state.")
                else:
                    st.error("Failed to create model from new data.")
            else:
                st.error(hosts_data)
                show_data = False

    if show_data:
        if 'nessus_data' in st.session_state or saved_data is not None:
            vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
            hosts_data = st.session_state['nessus_data']['hosts_data']

            if isinstance(hosts_data, list) and all(isinstance(i, dict) for i in hosts_data):
                st.subheader("Vulnerabilities Summary")
                col1, col2 = st.columns(2)
                with col1:
                    for severity, count in vulnerabilities.items():
                        if severity != 'Info':
                            st.metric(label=severity, value=count)
                with col2:
                    fig = go.Figure(data=[go.Pie(labels=list(vulnerabilities.keys()), values=list(vulnerabilities.values()), hole=.3)])
                    fig.update_layout(title="Vulnerability Distribution")
                    st.plotly_chart(fig)

                st.subheader("Host Data")
                st.dataframe(pd.DataFrame(hosts_data))
            else:
                st.error("hosts_data is not in the expected format. It should be a list of dictionaries.")
                st.write("Current hosts_data:", hosts_data)
        else:
            st.warning("No Nessus data available. Please fetch new data.")

# Organization Information section
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

# Data Input section
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
        if 'nessus_data' in st.session_state:
            vulnerabilities = st.session_state['nessus_data']['vulnerabilities']

            st.write("Vulnerabilities data (raw):", vulnerabilities)

            if isinstance(vulnerabilities, dict):
                total_vulns = sum(vulnerabilities.get(severity, 0) for severity in ['Critical', 'High', 'Medium', 'Low'])
                st.write(f"Total vulnerabilities detected: {total_vulns}")
                metrics['Critical'] = st.number_input("Critical Vulnerabilities", 0, 1000, vulnerabilities.get('Critical', 0))
                metrics['High'] = st.number_input("High Vulnerabilities", 0, 1000, vulnerabilities.get('High', 0))
                metrics['Medium'] = st.number_input("Medium Vulnerabilities", 0, 1000, vulnerabilities.get('Medium', 0))
                metrics['Low'] = st.number_input("Low Vulnerabilities", 0, 1000, vulnerabilities.get('Low', 0))
                metrics['Info'] = st.number_input("Informational Vulnerabilities", 0, 1000, vulnerabilities.get('Info', 0))
            else:
                st.error("Vulnerabilities data is not in the expected format")
        else:
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                metrics[severity] = st.number_input(f"{severity} Vulnerabilities", 0, 1000, 0)

        if st.button("Save Data"):
            st.session_state['metrics'] = metrics
            st.success("Data saved successfully!")

# Risk Assessment section
elif page == "Risk Assessment":
    st.header("Risk Assessment")

    if 'metrics' not in st.session_state:
        st.error("Please input data in the Data Input page first.")
    elif 'model' not in st.session_state or 'scaler' not in st.session_state:
        st.error("Please fetch Nessus data to create and train the model first.")
    else:
        metrics = st.session_state['metrics']
        model = st.session_state['model']
        scaler = st.session_state['scaler']

        input_data = np.array([[metrics.get('identify', 1), metrics.get('protect', 1), metrics.get('detect', 1),
                                metrics.get('respond', 1), metrics.get('recover', 1), metrics.get('govern', 1),
                                metrics.get('Critical', 0), metrics.get('High', 0), metrics.get('Medium', 0),
                                metrics.get('Low', 0), metrics.get('Info', 0)]], dtype=np.float64)

        input_scaled = scaler.transform(input_data)
        try:
            risk_level = model.predict(input_scaled)[0]
            risk_proba = model.predict_proba(input_scaled)[0]
        except Exception as e:
            st.error(f"An error occurred during risk assessment: {e}")
            risk_level = 'Unknown'
            risk_proba = [0, 0, 0]

        st.subheader("Current Risk Assessment")
        st.write(f"Predicted Risk Level: {risk_level}")

        fig = go.Figure(data=[go.Bar(x=['Low', 'Medium', 'High'], y=risk_proba)])
        fig.update_layout(title="Risk Level Probabilities", xaxis_title="Risk Level", yaxis_title="Probability")
        st.plotly_chart(fig)

# Attack Simulation section
elif page == "Attack Simulation":
    st.header("Attack Simulation")

    if 'metrics' not in st.session_state:
        st.error("Please complete the Risk Assessment first.")
    elif 'model' not in st.session_state or 'scaler' not in st.session_state:
        st.error("Please fetch Nessus data to create and train the model first.")
    else:
        metrics = st.session_state['metrics'].copy()
        model = st.session_state['model']
        scaler = st.session_state['scaler']

        st.subheader("Simulation Controls")
        attack_type = st.selectbox("Select Attack Type", ["malware", "phishing", "ddos", "data_breach"])

        if st.button("Run Simulation"):
            new_metrics, impact = simulate_attack(attack_type, metrics.copy())

            input_data = np.array([[new_metrics.get('identify', 1), new_metrics.get('protect', 1),
                                    new_metrics.get('detect', 1), new_metrics.get('respond', 1),
                                    new_metrics.get('recover', 1), new_metrics.get('govern', 1),
                                    new_metrics.get('Critical', 0), new_metrics.get('High', 0),
                                    new_metrics.get('Medium', 0), new_metrics.get('Low', 0),
                                    new_metrics.get('Info', 0)]], dtype=np.float64)

            input_scaled = scaler.transform(input_data)
            try:
                new_risk_level = model.predict(input_scaled)[0]
                new_risk_proba = model.predict_proba(input_scaled)[0]
            except Exception as e:
                st.error(f"An error occurred during attack simulation: {e}")
                new_risk_level = 'Unknown'
                new_risk_proba = [0, 0, 0]

            st.subheader("Post-Attack Risk Assessment")
            st.write(f"New Predicted Risk Level: {new_risk_level}")

            # Get pre-attack risk probabilities
            pre_input_data = np.array([[metrics.get('identify', 1), metrics.get('protect', 1),
                                        metrics.get('detect', 1), metrics.get('respond', 1),
                                        metrics.get('recover', 1), metrics.get('govern', 1),
                                        metrics.get('Critical', 0), metrics.get('High', 0),
                                        metrics.get('Medium', 0), metrics.get('Low', 0),
                                        metrics.get('Info', 0)]], dtype=np.float64)
            pre_input_scaled = scaler.transform(pre_input_data)
            pre_risk_proba = model.predict_proba(pre_input_scaled)[0]

            fig = go.Figure(data=[
                go.Bar(name='Before Attack', x=['Low', 'Medium', 'High'], y=pre_risk_proba),
                go.Bar(name='After Attack', x=['Low', 'Medium', 'High'], y=new_risk_proba)
            ])
            fig.update_layout(title="Risk Level Probabilities Comparison", xaxis_title="Risk Level",
                              yaxis_title="Probability", barmode='group')
            st.plotly_chart(fig)

            st.session_state['metrics'] = new_metrics
            st.success("Metrics updated after the attack simulation.")

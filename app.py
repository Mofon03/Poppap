import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression
import joblib
import os
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests

# ปิดการเตือนเกี่ยวกับ SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ตั้งค่าการแสดงผลของหน้าเว็บ
st.set_page_config(page_title="AI-powered Cybersecurity Risk Assessment", layout="wide")

# ฟังก์ชันช่วยเหลือ
def save_model(model, filename):
    joblib.dump(model, filename)

def load_model(filename):
    return joblib.load(filename)

def save_data_to_json(data, filename='nessus_data.json'):
    with open(filename, 'w') as f:
        json.dump(data, f)

def load_data_from_json(filename='nessus_data.json'):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return None

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
            severity_counts = host.get('severity_counts', {})
            for severity in vulnerabilities.keys():
                count = severity_counts.get(severity.upper(), 0)
                vulnerabilities[severity] += count

            hosts_data.append({
                'Host': host.get('hostname', 'Unknown'),
                'Critical': severity_counts.get('CRITICAL', 0),
                'High': severity_counts.get('HIGH', 0),
                'Medium': severity_counts.get('MEDIUM', 0),
                'Low': severity_counts.get('LOW', 0),
                'Info': severity_counts.get('INFO', 0)
            })

        # คำนวณคะแนน NIST CSF จากข้อมูลช่องโหว่
        nist_scores = calculate_nist_scores(vulnerabilities)

        return vulnerabilities, hosts_data, nist_scores
    except requests.exceptions.RequestException as e:
        return None, f"Error fetching data from Nessus: {str(e)}"

def calculate_nist_scores(vulnerabilities):
    # กำหนดน้ำหนักของแต่ละระดับความรุนแรงต่อฟังก์ชัน NIST CSF
    weights = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Info': 0
    }
    total_vulns = sum(vulnerabilities.values())
    nist_functions = ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']
    scores = {}
    for func in nist_functions:
        score = 0
        for severity, count in vulnerabilities.items():
            score += weights[severity] * count
        # ปรับคะแนนให้อยู่ในช่วง 1 ถึง 4
        if total_vulns > 0:
            score = max(1, 4 - int((score / (total_vulns * 4)) * 3))
        else:
            score = 4
        scores[func] = score
    return scores

@st.cache_resource
def create_model(vulnerabilities_data, nist_scores_data):
    if not isinstance(vulnerabilities_data, list) or not all(isinstance(item, dict) for item in vulnerabilities_data):
        st.error("Invalid vulnerability data format")
        return None, None

    try:
        data = pd.DataFrame(vulnerabilities_data)
        n_samples = len(vulnerabilities_data)
        for feature in ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']:
            data[feature] = nist_scores_data.get(feature, 1)

        data['risk_level'] = pd.cut(data['Critical'] + data['High'] + data['Medium'],
                                    bins=[-1, 10, 30, float('inf')],
                                    labels=['Low', 'Medium', 'High'])

        for column in data.columns:
            if data[column].dtype.name == 'category':
                data[column] = data[column].cat.add_categories(['Unknown']).fillna('Unknown')
            else:
                data[column].fillna(0, inplace=True)

        X = data[['identify', 'protect', 'detect', 'respond', 'recover', 'govern',
                  'Critical', 'High', 'Medium', 'Low', 'Info']]
        y = data['risk_level']

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_scaled, y)

        return model, scaler
    except Exception as e:
        st.error(f"Error creating model: {str(e)}")
        return None, None

def nist_csf_analysis():
    st.header("Detailed NIST CSF 2.0 Analysis")

    if 'nessus_data' not in st.session_state or 'vulnerabilities' not in st.session_state['nessus_data']:
        st.warning("No vulnerability data available. Please fetch data from Nessus first.")
        return

    vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
    vuln_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    vuln_counts = [vulnerabilities.get(level, 0) for level in vuln_levels]
    nist_functions = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover', 'Govern']

    # ส่วนที่ 1: แสดงข้อมูลช่องโหว่ตามระดับความรุนแรง
    st.subheader("Summary of Vulnerability Severity Levels")
    vuln_df = pd.DataFrame({
        'Severity': vuln_levels,
        'Count': vuln_counts
    })
    severity_colors = {
        'Critical': 'red',
        'High': 'orange',
        'Medium': 'yellow',
        'Low': 'lightgreen',
        'Info': 'gray'
    }
    fig_vuln = px.bar(vuln_df, x='Severity', y='Count', title='Number of Vulnerabilities by Severity', text='Count',
                      color='Severity', color_discrete_map=severity_colors)
    fig_vuln.update_traces(textposition='outside')
    st.plotly_chart(fig_vuln)

    # ส่วนที่ 2: แสดงค่าฟังก์ชัน NIST CSF 2.0
    st.subheader("NIST CSF 2.0 Function Scores")
    if 'metrics' in st.session_state:
        metrics = st.session_state['metrics']
        nist_scores = [metrics.get(func.lower(), 0) for func in nist_functions]
        nist_df = pd.DataFrame({
            'Function': nist_functions,
            'Score': nist_scores
        })
        fig_nist = px.bar(nist_df, x='Function', y='Score', title='NIST CSF 2.0 Function Scores', range_y=[0,4], text='Score')
        fig_nist.update_traces(textposition='outside', marker_color='steelblue')
        st.plotly_chart(fig_nist)
    else:
        st.warning("No NIST CSF 2.0 scores available. Please input data in the Data Input page.")

    # ส่วนที่ 3: แสดงความสัมพันธ์ระหว่างช่องโหว่และฟังก์ชัน NIST CSF 2.0
    st.subheader("Relationship between Vulnerabilities and NIST CSF Functions")
    # สมมุติความสัมพันธ์ระหว่างระดับความรุนแรงกับฟังก์ชัน NIST CSF 2.0
    vuln_nist_relation = {
        'Critical': [0.9, 0.9, 0.8, 0.7, 0.6, 0.8],
        'High': [0.7, 0.8, 0.6, 0.5, 0.4, 0.6],
        'Medium': [0.5, 0.6, 0.4, 0.3, 0.3, 0.4],
        'Low': [0.3, 0.4, 0.2, 0.2, 0.2, 0.2],
        'Info': [0.1, 0.2, 0.1, 0.1, 0.1, 0.1]
    }

    # สร้าง DataFrame สำหรับ Heatmap
    data = []
    for severity in vuln_levels:
        for idx, function in enumerate(nist_functions):
            data.append({
                'Severity': severity,
                'Function': function,
                'Impact': vuln_nist_relation[severity][idx] * vulnerabilities.get(severity, 0)
            })

    impact_df = pd.DataFrame(data)

    # สร้าง Heatmap
    impact_pivot = impact_df.pivot(index='Severity', columns='Function', values='Impact')
    fig_heatmap = px.imshow(
        impact_pivot,
        labels=dict(x="NIST CSF 2.0 Functions", y="Severity Level", color="Impact"),
        x=nist_functions,
        y=vuln_levels,
        color_continuous_scale='Reds'
    )
    fig_heatmap.update_layout(title="Impact of Vulnerabilities on NIST CSF 2.0 Functions")
    st.plotly_chart(fig_heatmap)

def traditional_comparison():
    st.header("Comparison with Traditional Assessment")

    if 'metrics' not in st.session_state:
        st.warning("No AI assessment data available. Please perform risk assessment first.")
        return

    traditional_assessment = {}
    for function in ['Identify', 'Protect', 'Detect', 'Respond', 'Recover', 'Govern']:
        traditional_assessment[function] = st.slider(f"Traditional {function} Score", 1, 4, 2)

    ai_assessment = {k.capitalize(): v for k, v in st.session_state['metrics'].items() if k in ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']}

    comparison_data = pd.DataFrame({
        'Function': ai_assessment.keys(),
        'AI Assessment': ai_assessment.values(),
        'Traditional Assessment': [traditional_assessment.get(func, 0) for func in ai_assessment.keys()]
    })

    fig = px.bar(comparison_data, x='Function', y=['AI Assessment', 'Traditional Assessment'],
                 title="Comparison of AI and Traditional Assessments",
                 barmode='group')
    st.plotly_chart(fig)

def enhanced_attack_simulation():
    st.header("Advanced Attack Simulation")

    if 'metrics' not in st.session_state:
        st.error("No assessment data available. Please perform risk assessment first.")
        return

    if 'model' not in st.session_state or 'scaler' not in st.session_state:
        st.error("No AI model available. Please fetch data from Nessus and create the model first.")
        return

    attack_types = {
        "Ransomware": {"identify": -2, "protect": -3, "detect": -1, "respond": -2, "recover": -3, "govern": -1},
        "DDoS": {"identify": -1, "protect": -2, "detect": -2, "respond": -3, "recover": -1, "govern": -1},
        "Phishing": {"identify": -1, "protect": -2, "detect": -1, "respond": -1, "recover": -1, "govern": -2},
        "SQL Injection": {"identify": -2, "protect": -3, "detect": -2, "respond": -2, "recover": -2, "govern": -1}
    }

    selected_attack = st.selectbox("Select Attack Type", list(attack_types.keys()))

    if st.button("Simulate Attack"):
        current_assessment = st.session_state['metrics'].copy()
        impact = attack_types[selected_attack]

        # Apply impact
        for func, change in impact.items():
            if func in current_assessment:
                current_assessment[func] = max(1, current_assessment[func] + change)

        st.subheader(f"Impact of {selected_attack} Attack on NIST CSF 2.0 Functions")

        functions = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover', 'Govern']
        before_attack = [st.session_state['metrics'][func.lower()] for func in functions]
        after_attack = [current_assessment[func.lower()] for func in functions]

        # แสดงกราฟ Before Attack
        fig_before = go.Figure()
        fig_before.add_trace(go.Bar(
            x=functions,
            y=before_attack,
            name='Before Attack',
            marker_color='steelblue'
        ))
        fig_before.update_layout(
            title="NIST CSF 2.0 Function Scores Before Attack",
            xaxis_title="NIST CSF 2.0 Functions",
            yaxis_title="Score",
            yaxis=dict(range=[0,4])
        )
        st.plotly_chart(fig_before)

        # แสดงกราฟ After Attack
        fig_after = go.Figure()
        fig_after.add_trace(go.Bar(
            x=functions,
            y=after_attack,
            name='After Attack',
            marker_color='crimson'
        ))
        fig_after.update_layout(
            title="NIST CSF 2.0 Function Scores After Attack",
            xaxis_title="NIST CSF 2.0 Functions",
            yaxis_title="Score",
            yaxis=dict(range=[0,4])
        )
        st.plotly_chart(fig_after)

        # สร้างกราฟ Delta Impact
        impact_delta = np.array(after_attack) - np.array(before_attack)
        fig_delta = go.Figure()
        fig_delta.add_trace(go.Bar(
            x=functions,
            y=impact_delta,
            name='Change',
            marker_color='darkorange'
        ))
        fig_delta.update_layout(
            title="Change in NIST CSF 2.0 Function Scores (After - Before Attack)",
            xaxis_title="NIST CSF 2.0 Functions",
            yaxis_title="Score Change",
            yaxis=dict(range=[-4,4])
        )
        st.plotly_chart(fig_delta)

        # Perform risk assessment with new metrics
        model = st.session_state['model']
        scaler = st.session_state['scaler']

        input_data = np.array([[current_assessment.get('identify', 1), current_assessment.get('protect', 1),
                                current_assessment.get('detect', 1), current_assessment.get('respond', 1),
                                current_assessment.get('recover', 1), current_assessment.get('govern', 1),
                                current_assessment.get('Critical', 0), current_assessment.get('High', 0),
                                current_assessment.get('Medium', 0), current_assessment.get('Low', 0),
                                current_assessment.get('Info', 0)]], dtype=np.float64)

        input_scaled = scaler.transform(input_data)
        risk_proba = model.predict_proba(input_scaled)[0]
        risk_levels = model.classes_
        max_prob_idx = np.argmax(risk_proba)
        new_risk_level = risk_levels[max_prob_idx]

        # ตรวจสอบระดับความเสี่ยงให้ครบถ้วน
        expected_risk_levels = ['Low', 'Medium', 'High']
        for level in expected_risk_levels:
            if level not in risk_levels:
                risk_levels = np.append(risk_levels, level)
                risk_proba = np.append(risk_proba, 0)

        # จัดเรียงระดับความเสี่ยง
        order = [expected_risk_levels.index(level) for level in risk_levels]
        risk_levels = risk_levels[order]
        risk_proba = risk_proba[order]

        st.subheader("Risk Assessment After Attack")
        st.write(f"New predicted risk level: {new_risk_level}")

        # กำหนดสีสำหรับระดับความเสี่ยง
        risk_color_mapping = {
            'Low': 'lightgreen',
            'Medium': 'orange',
            'High': 'red'
        }

        fig = go.Figure(data=[go.Bar(
            x=risk_levels,
            y=risk_proba,
            marker_color=[risk_color_mapping.get(level, 'gray') for level in risk_levels]
        )])
        fig.update_layout(
            title="Probability of New Risk Levels",
            xaxis_title="Risk Levels",
            yaxis_title="Probability",
            yaxis=dict(range=[0,1])
        )
        st.plotly_chart(fig)

def trend_analysis_and_prediction():
    st.header("Trend Analysis and Prediction")

    # ในสถานการณ์จริง คุณควรใช้ข้อมูลประวัติจริง
    historical_data = pd.DataFrame({
        'Date': pd.date_range(start='1/1/2023', periods=12, freq='M'),
        'Risk_Score': np.random.randint(50, 100, 12)
    })

    fig = px.line(historical_data, x='Date', y='Risk_Score', title='Historical Risk Trend')
    st.plotly_chart(fig)

    X = np.array(range(len(historical_data))).reshape(-1, 1)
    y = historical_data['Risk_Score'].values

    model = LinearRegression()
    model.fit(X, y)

    future_dates = pd.date_range(start=historical_data['Date'].max(), periods=6, freq='M')[1:]
    future_X = np.array(range(len(historical_data), len(historical_data) + len(future_dates))).reshape(-1, 1)
    future_y = model.predict(future_X)

    future_df = pd.DataFrame({'Date': future_dates, 'Risk_Score': future_y})

    combined_df = pd.concat([historical_data, future_df], ignore_index=True)

    fig = px.line(combined_df, x='Date', y='Risk_Score', title='Risk Trend and Forecast')
    st.plotly_chart(fig)

def generate_report_and_recommendations():
    st.header("Report and Recommendations")

    if 'metrics' not in st.session_state:
        st.error("No assessment data available. Please perform risk assessment first.")
        return

    current_assessment = st.session_state['metrics']

    st.subheader("Summary Report")
    for func, score in current_assessment.items():
        if func in ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']:
            st.write(f"{func.capitalize()}: {score}/4")

    st.subheader("Recommendations")
    recommendations = {
        "identify": "Improve asset management and risk assessment processes.",
        "protect": "Enhance access controls and conduct regular security training.",
        "detect": "Upgrade intrusion detection systems and improve log monitoring.",
        "respond": "Develop and regularly test incident response plans.",
        "recover": "Implement robust backup and disaster recovery solutions.",
        "govern": "Establish clear cybersecurity policies and conduct regular audits."
    }

    for func, score in current_assessment.items():
        if func in recommendations and score < 3:
            st.write(f"**{func.capitalize()}:** {recommendations[func]}")

    # Add overall risk level if available
    if 'risk_level' in st.session_state:
        st.subheader("Overall Risk Assessment")
        st.write(f"Current risk level: {st.session_state['risk_level']}")

    # เพิ่มสรุปช่องโหว่ถ้ามี
    if 'nessus_data' in st.session_state and 'vulnerabilities' in st.session_state['nessus_data']:
        st.subheader("Vulnerability Summary")
        vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
        for severity, count in vulnerabilities.items():
            st.write(f"{severity}: {count}")

    # เพิ่มข้อมูลเชิงลึกเพิ่มเติม
    st.subheader("Additional Insights")
    st.write("Based on the current assessment, consider the following general recommendations:")
    st.write("1. Regularly update and patch all systems and software.")
    st.write("2. Implement multi-factor authentication for all critical systems.")
    st.write("3. Conduct regular cybersecurity training for all employees.")
    st.write("4. Perform continuous penetration testing and vulnerability assessments.")
    st.write("5. Develop and maintain incident response plans, and test them regularly.")

def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Home", "Connect to Nessus", "Organization Info", "Data Input",
                                      "Risk Assessment", "NIST CSF Analysis", "Traditional Comparison",
                                      "Attack Simulation", "Trend Analysis", "Report"])

    if page == "Home":
        st.title("AI-powered Cybersecurity Risk Assessment using NIST CSF 2.0")
        st.write("Welcome to the AI-powered Cybersecurity Risk Assessment application using NIST CSF 2.0. Use the sidebar to navigate through different sections of the application.")

    elif page == "Connect to Nessus":
        st.header("Connect to Nessus")

        nessus_url = st.text_input("Nessus URL", value="https://localhost:8834")
        access_key = st.text_input("Access Key", value="your_access_key_here")
        secret_key = st.text_input("Secret Key", value="your_secret_key_here", type="password")
        scan_id = st.number_input("Scan ID", min_value=1, value=1)

        show_data = False  # Initialize show_data

        saved_data = load_data_from_json()
        if saved_data is not None:
            if 'nessus_data' not in st.session_state:
                st.session_state['nessus_data'] = saved_data

            if st.button("Use Existing Data"):
                vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
                hosts_data = st.session_state['nessus_data']['hosts_data']
                nist_scores = st.session_state['nessus_data']['nist_scores']
                st.success("Loaded data from JSON file")
                st.write("Current Host Data:", hosts_data)
                show_data = True

                # Create and store the model and scaler using existing data
                model, scaler = create_model(hosts_data, nist_scores)
                if model and scaler:
                    st.session_state['model'] = model
                    st.session_state['scaler'] = scaler
                    st.success("Model created and stored in session state")
                else:
                    st.error("Unable to create model from existing data")

        if st.button("Test Nessus Connection"):
            success, message = test_nessus_connection(nessus_url, access_key, secret_key)
            if success:
                st.success(message)
            else:
                st.error(message)

        if st.button("Fetch New Nessus Data"):
            result = get_nessus_data(nessus_url, access_key, secret_key, scan_id)
            if isinstance(result, tuple) and len(result) == 3:
                vulnerabilities, hosts_data, nist_scores = result
                st.session_state['nessus_data'] = {'vulnerabilities': vulnerabilities, 'hosts_data': hosts_data, 'nist_scores': nist_scores}
                save_data_to_json(st.session_state['nessus_data'])
                st.success("Fetched and saved new Nessus data")
                st.write("Current Host Data:", hosts_data)
                show_data = True

                # Create and store the model and scaler
                model, scaler = create_model(hosts_data, nist_scores)
                if model and scaler:
                    st.session_state['model'] = model
                    st.session_state['scaler'] = scaler
                    st.success("Model created and stored in session state")
                else:
                    st.error("Unable to create model from new data")
            else:
                st.error(result)
                show_data = False

        if show_data:
            if 'nessus_data' in st.session_state:
                vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
                hosts_data = st.session_state['nessus_data']['hosts_data']

                st.subheader("Vulnerability Summary")
                vuln_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
                vuln_counts = [vulnerabilities.get(level, 0) for level in vuln_levels]
                severity_colors = {
                    'Critical': 'red',
                    'High': 'orange',
                    'Medium': 'yellow',
                    'Low': 'lightgreen',
                    'Info': 'gray'
                }

                vuln_df = pd.DataFrame({
                    'Severity': vuln_levels,
                    'Count': vuln_counts
                })

                fig_vuln = px.pie(vuln_df, names='Severity', values='Count', title='Distribution of Vulnerabilities',
                                  color='Severity', color_discrete_map=severity_colors)
                st.plotly_chart(fig_vuln)

                st.subheader("Host Data")
                st.dataframe(pd.DataFrame(hosts_data))
            else:
                st.warning("No Nessus data available. Please fetch new data or use existing data.")

    elif page == "Organization Info":
        st.header("Organization Information")

        org_name = st.text_input("Organization Name")
        org_size = st.selectbox("Organization Size", ["Small", "Medium", "Large"])
        industry = st.selectbox("Industry", ["Finance", "Healthcare", "Technology", "Retail", "Manufacturing", "Other"])
        contact_name = st.text_input("Contact Name")
        contact_email = st.text_input("Contact Email")

        if st.button("Save Organization Info"):
            st.session_state['org_info'] = {
                'name': org_name,
                'size': org_size,
                'industry': industry,
                'contact_name': contact_name,
                'contact_email': contact_email
            }
            st.success("Organization information saved!")

    elif page == "Data Input":
        st.header("Data Input")

        if 'org_info' not in st.session_state:
            st.warning("Please enter organization information first.")
        else:
            st.subheader("NIST CSF 2.0 Capabilities")
            metrics = {}
            default_scores = {
                'identify': 3,
                'protect': 2,
                'detect': 4,
                'respond': 2,
                'recover': 3,
                'govern': 1
            }
            for metric in ['identify', 'protect', 'detect', 'respond', 'recover', 'govern']:
                metrics[metric] = st.slider(f"{metric.capitalize()} Capability", 1, 4, default_scores.get(metric, 3))

            st.subheader("Vulnerability Data")
            if 'nessus_data' in st.session_state:
                vulnerabilities = st.session_state['nessus_data']['vulnerabilities']
                total_vulns = sum(vulnerabilities.get(severity, 0) for severity in ['Critical', 'High', 'Medium', 'Low'])
                st.write(f"Total vulnerabilities found: {total_vulns}")
                for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                    metrics[severity] = st.number_input(f"{severity} Vulnerabilities", 0, 1000, vulnerabilities.get(severity, 0))
            else:
                for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                    metrics[severity] = st.number_input(f"{severity} Vulnerabilities", 0, 1000, 0)

            if st.button("Save Data"):
                st.session_state['metrics'] = metrics
                st.success("Data saved!")

    elif page == "Risk Assessment":
        st.header("Risk Assessment")

        if 'metrics' not in st.session_state:
            st.error("Please input data in the Data Input page first.")
        elif 'model' not in st.session_state or 'scaler' not in st.session_state:
            st.error("Please fetch data from Nessus to create and train the model first.")
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
                risk_proba = model.predict_proba(input_scaled)[0]
                risk_levels = model.classes_
                max_prob_idx = np.argmax(risk_proba)
                risk_level = risk_levels[max_prob_idx]

                # ตรวจสอบระดับความเสี่ยงให้ครบถ้วน
                expected_risk_levels = ['Low', 'Medium', 'High']
                for level in expected_risk_levels:
                    if level not in risk_levels:
                        risk_levels = np.append(risk_levels, level)
                        risk_proba = np.append(risk_proba, 0)

                # จัดเรียงระดับความเสี่ยง
                order = [expected_risk_levels.index(level) for level in risk_levels]
                risk_levels = risk_levels[order]
                risk_proba = risk_proba[order]

                st.session_state['risk_level'] = risk_level
                st.session_state['risk_proba'] = risk_proba
            except Exception as e:
                st.error(f"Error during risk assessment: {e}")
                risk_level = 'Unknown'
                risk_proba = [0, 0, 0]

            st.subheader("Current Risk Assessment")
            st.write(f"Predicted risk level: {risk_level}")

            # กำหนดสีสำหรับระดับความเสี่ยง
            risk_color_mapping = {
                'Low': 'lightgreen',
                'Medium': 'orange',
                'High': 'red'
            }

            fig = go.Figure(data=[go.Bar(
                x=risk_levels,
                y=risk_proba,
                marker_color=[risk_color_mapping.get(level, 'gray') for level in risk_levels]
            )])
            fig.update_layout(
                title="Probability of Risk Levels",
                xaxis_title="Risk Levels",
                yaxis_title="Probability",
                yaxis=dict(range=[0,1])
            )
            st.plotly_chart(fig)

    elif page == "NIST CSF Analysis":
        nist_csf_analysis()

    elif page == "Traditional Comparison":
        traditional_comparison()

    elif page == "Attack Simulation":
        enhanced_attack_simulation()

    elif page == "Trend Analysis":
        trend_analysis_and_prediction()

    elif page == "Report":
        generate_report_and_recommendations()

if __name__ == "__main__":
    main()

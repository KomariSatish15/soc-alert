import streamlit as st
import pandas as pd
import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import plotly.express as px
import joblib
import io
import plotly.graph_objects as go
from scipy.stats import gaussian_kde
import networkx as nx
from pyvis.network import Network

st.set_page_config(page_title="SOC Alert Prioritization System for Darknet", layout="wide")

# Load the dataset
@st.cache_data(ttl=36)
def load_data():
    data = pd.read_csv('Darknet.csv')
    return data

st.markdown(
    "<h1 style='text-align: center; color: white;'>SOC Alert Prioritization System for Darknet</h1>",
    unsafe_allow_html=True
)


df = load_data()
st.markdown(
    "<h3 style='text-align: center; color: white; text-decoration: underline;'>Darknet Log Data</h3>",
    unsafe_allow_html=True
)

st.dataframe(df.head(7))


with st.expander("🔍 Column Descriptions", expanded=False):
    st.markdown("""
    | Column | Description |
    |--------|-------------|
    | `Flow ID` | Unique identifier for the network flow |
    | `Src IP`, `Dst IP` | Source and Destination IP addresses |
    | `Src Port`, `Dst Port` | Source and Destination port numbers |
    | `Protocol` | Protocol used (e.g., TCP, UDP) |
    | `Timestamp` | Time when the flow started |
    | `Flow Duration` | Duration of the flow in microseconds |
    | `Total Fwd Packet`, `Total Bwd packets` | Number of packets sent forward/backward |
    | `Total Length of Fwd Packet`, `Total Length of Bwd Packet` | Total size of forward/backward packets |
    | `Fwd Packet Length Max/Min/Mean/Std` | Stats of forward packet lengths |
    | `Bwd Packet Length Max/Min/Mean/Std` | Stats of backward packet lengths |
    | `Flow Bytes/s`, `Flow Packets/s` | Data and packet transfer rates |
    | `Flow IAT Mean/Std/Max/Min` | Inter-arrival time stats for flow |
    | `Fwd IAT Total/Mean/Std/Max/Min` | Inter-arrival time stats for forward packets |
    | `Bwd IAT Total/Mean/Std/Max/Min` | Inter-arrival time stats for backward packets |
    | `Fwd PSH Flags`, `Bwd PSH Flags` | PSH flags in forward/backward direction |
    | `Fwd URG Flags`, `Bwd URG Flags` | URG flags in forward/backward direction |
    | `Fwd Header Length`, `Bwd Header Length` | Header sizes in forward/backward direction |
    | `Fwd Packets/s`, `Bwd Packets/s` | Packet rates in both directions |
    | `Packet Length Min/Max/Mean/Std/Variance` | General packet size statistics |
    | `FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count` | Various TCP flag counts |
    | `Down/Up Ratio` | Ratio of download to upload traffic |
    | `Average Packet Size` | Mean packet size in the flow |
    | `Fwd/Bwd Segment Size Avg` | Avg segment size in forward/backward |
    | `Fwd/Bwd Bytes/Bulk Avg` | Avg bulk bytes in either direction |
    | `Fwd/Bwd Packet/Bulk Avg` | Avg bulk packets in either direction |
    | `Fwd/Bwd Bulk Rate Avg` | Bulk rate per direction |
    | `Subflow Fwd/Bwd Packets` | Number of packets in subflows |
    | `Subflow Fwd/Bwd Bytes` | Number of bytes in subflows |
    | `FWD/Bwd Init Win Bytes` | Initial TCP window bytes |
    | `Fwd Act Data Pkts` | Forward active data packets |
    | `Fwd Seg Size Min` | Minimum segment size in forward |
    | `Active Mean/Std/Max/Min` | Flow active time stats |
    | `Idle Mean/Std/Max/Min` | Flow idle time stats |
    | `Label` | Type of traffic (e.g., BENIGN, DoS, etc.) |
    """)





df = pd.read_csv("Darknet.csv")

# Session state to track active tab
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 'Traffic'






# Button tabs using columns
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("📦  SOC Alerts"):
        st.session_state.active_tab = 'Alerts'

with col2:
    if st.button("📊 Distribution Analysis"):
        st.session_state.active_tab = 'Distribution Analysis'

with col3:
    if st.button("🛰️ Category Analysis"):
        st.session_state.active_tab = 'Category Analysis'




# Render different content based on active tab
tab = st.session_state.active_tab

# st.markdown(f"### You selected: {tab}")

if st.session_state.active_tab == "Distribution Analysis":
    
    st.markdown("### 📊 Distribution Analysis (Log-Transformed for Skewed Data)")

    important_cols = [
        "Flow Duration", "Total Fwd Packet", "Total Bwd packets", 
        "Total Length of Fwd Packet", "Total Length of Bwd Packet", 
        "Flow Bytes/s", "Flow Packets/s", 
        "Fwd Packet Length Max", "Bwd Packet Length Max",
        "Packet Length Mean", "ACK Flag Count", "Idle Mean",
        "Fwd Packets/s", "Bwd Packets/s", "Average Packet Size"
    ]

    for i in range(0, len(important_cols), 3):
        cols = st.columns(3)
        for j in range(3):
            if i + j < len(important_cols):
                with cols[j]:
                    col_name = important_cols[i + j]
                    data = df[col_name]
                    
                    # Apply log1p only if all values are >= 0
                    if (data >= 0).all():
                        data = np.log1p(data)
                        title = f"{col_name} (Log Transformed)"
                    else:
                        title = col_name

                    fig = px.histogram(data_frame=pd.DataFrame({title: data}), x=title, nbins=50, color_discrete_sequence=["#FF6F61"])
                    st.plotly_chart(fig, use_container_width=True)

elif tab == "Category Analysis":

    # Select categorical columns for value count analysis
    categorical_columns = [ 'Src IP', 'Dst IP', 'Src Port', 'Dst Port',  'Protocol', 'Label']  # You can add more categorical columns as needed
    df['Src Port'] = df['Src Port'].astype(str)
    df['Dst Port'] = df['Dst Port'].astype(str)

    def plot_bar_pie_side_by_side(column, top_n=10):
        value_counts = df[column].value_counts().head(top_n)

        # Format counts in 'k'
        formatted_counts = [f"{v/1000:.1f}k" for v in value_counts.values]

        # Bar Chart
        bar_fig = px.bar(
            x=value_counts.index,
            y=value_counts.values,
            labels={'x': column, 'y': 'Count'},
            title=f"Top {top_n} {column} - Bar Chart"
        )
        bar_fig.update_traces(
            text=formatted_counts, textposition='outside',
            marker=dict(color='orange', line=dict(color='black', width=1))
        )
        if column in ['Src Port', 'Dst Port', 'Protocol']:
            bar_fig.update_layout(xaxis_type='category')

        # Pie Chart
        pie_fig = px.pie(
            names=value_counts.index,
            values=value_counts.values,
            title=f"Top {top_n} {column} - Pie Chart",
            hole=0.3  # Donut style
        )
        pie_fig.update_traces(textinfo='percent+label')

        return bar_fig, pie_fig

    # Streamlit display
    with st.expander("📊 Categorical Column Breakdown", expanded=True):
        for i, col in enumerate(categorical_columns):
            st.subheader(f"🔹 {col}")
            col1, col2 = st.columns(2)
            with col1:
                bar, pie = plot_bar_pie_side_by_side(col, top_n=10)
                st.plotly_chart(bar, use_container_width=True)
            with col2:
                st.plotly_chart(pie, use_container_width=True)

elif tab == "Alerts":

    st.markdown("Gain a quick business-friendly summary of possible security events from the darknet logs.")

    alert_col1, alert_col2 = st.columns(2)

    # 📊 Activity Counts by Label
    with alert_col1:
        st.markdown("### 🔐 Activity Categories")
        label_counts = df['Label1'].value_counts().reset_index()
        label_counts.columns = ['Label', 'Count']
        fig = px.bar(label_counts, x='Label', y='Count', color='Label',
                     text=label_counts['Count'].apply(lambda x: f"{x/1000:.1f}K" if x > 1000 else str(x)),
                     color_discrete_sequence=px.colors.qualitative.Set1)
        fig.update_traces(textposition='outside')
        fig.update_layout(height=400, xaxis_title=None, yaxis_title="Activity Count")
        st.plotly_chart(fig, use_container_width=True)


    with alert_col2:
        st.markdown("### 🔐 Label Categories")
        label_counts = df['Label'].value_counts().reset_index()
        label_counts.columns = ['Label', 'Count']
        fig = px.bar(label_counts, x='Label', y='Count', color='Label',
                     text=label_counts['Count'].apply(lambda x: f"{x/1000:.1f}K" if x > 1000 else str(x)),
                     color_discrete_sequence=px.colors.qualitative.Set1)
        fig.update_traces(textposition='outside')
        fig.update_layout(height=400, xaxis_title=None, yaxis_title="Activity Count")
        st.plotly_chart(fig, use_container_width=True)

    # ⏰ Hourly Alerts Trend
    # with alert_col2:
    #     st.markdown("### ⏰ Alerts Over Time (Hourly)")
    #     df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    #     df['Hour'] = df['Timestamp'].dt.hour
    #     hourly_alerts = df.groupby('Hour').size().reset_index(name='Count')
    #     fig = px.area(hourly_alerts, x='Hour', y='Count',
    #                   labels={'Count': 'Alerts'},
    #                   color_discrete_sequence=['#FF6F61'])
    #     fig.update_layout(height=400)
    #     st.plotly_chart(fig, use_container_width=True)

    st.divider()


    # Dynamic sliders
    # st.sidebar.header("🔧 Rule Thresholds")
    # fwd_packet = st.sidebar.slider("Forward Packet Threshold", 0, 100000, 10000)
    # flow_duration = st.sidebar.slider("Flow Duration Threshold", 0, 5_000_000, 1_000_000)
    # packet_length = st.sidebar.slider("Fwd Packet Length Max Threshold", 0, 3000, 1500)
    # backdoor_port = st.sidebar.number_input("Suspicious Port", value=4444)

    # thresholds = {
    #     'fwd_packet': fwd_packet,
    #     'flow_duration': flow_duration,
    #     'packet_length': packet_length,
    #     'backdoor_port': backdoor_port
    # }



    


    # Get the statistics of relevant columns
    min_fwd_packet = int(df['Total Fwd Packet'].min())  # Ensure min and max are integers
    max_fwd_packet = int(df['Total Fwd Packet'].max())

    min_flow_duration = int(df['Flow Duration'].min())  # Ensure min and max are integers
    max_flow_duration = int(df['Flow Duration'].max())

    min_packet_length = int(df['Fwd Packet Length Max'].min())  # Ensure min and max are integers
    max_packet_length = int(df['Fwd Packet Length Max'].max())

    # Dynamic sliders based on dataset stats
    st.sidebar.header("🔧 Rule Thresholds")

    # For Forward Packet Threshold
    fwd_packet = st.sidebar.slider(
        "Forward Packet Threshold", 
        min_fwd_packet, max_fwd_packet, 
        round((min_fwd_packet + max_fwd_packet) / 2)  # Default is midpoint
    )

    # For Flow Duration Threshold
    flow_duration = st.sidebar.slider(
        "Flow Duration Threshold", 
        min_flow_duration, max_flow_duration, 
        round((min_flow_duration + max_flow_duration) / 2)   # Default is midpoint
    )

    # For Packet Length Max Threshold
    packet_length = st.sidebar.slider(
        "Fwd Packet Length Max Threshold", 
        min_packet_length, max_packet_length, 
        round((min_packet_length + max_packet_length) / 2)  # Default is midpoint
    )

    # For Suspicious Port (Manually Set)
    backdoor_port = st.sidebar.number_input("Suspicious Port", value=6)

    # Thresholds dictionary
    thresholds = {
        'fwd_packet': fwd_packet,
        'flow_duration': flow_duration,
        'packet_length': packet_length,
        'backdoor_port': backdoor_port
    }

    def apply_alert_rules(row,thresholds):
        if row['Label'] == 'Tor':
            return 'CRITICAL'
        elif row['Label1'] == 'P2P':
            return 'HIGH'

        if row['Dst Port'] == thresholds['backdoor_port']:
            return 'HIGH'
        else:
            return 'LOW'

    # Rule Engine Function
    def apply_alert_rules1(row, thresholds):
        if row['Label1'] == 'TOR':
            return 'CRITICAL'
        if row['Label1'] == 'P2P':
            return 'HIGH'
        if row['Dst Port'] == thresholds['backdoor_port']:
            return 'HIGH'
        if row['Total Fwd Packet'] > thresholds['fwd_packet']:
            return 'MEDIUM'
        if row['Flow Duration'] > thresholds['flow_duration']:
            return 'MEDIUM'
        if row['Fwd Packet Length Max'] > thresholds['packet_length']:
            return 'HIGH'
        return 'LOW'

    # Apply the rule engine to the dataset
    df['ALERT_SEVERITY'] = df.apply(lambda row: apply_alert_rules(row, thresholds), axis=1)


    # Show alerts
    # st.dataframe(df[['Src IP', 'Dst IP', 'Dst Port', 'Flow Duration', 'Label1', 'ALERT_SEVERITY']].head(50))

    col1, col2 = st.columns(2)

    with col1:
        severity_count = df['ALERT_SEVERITY'].value_counts().reset_index()
        severity_count.columns = ['Severity', 'Count']
        fig1 = px.bar(severity_count, x='Severity', y='Count', color='Severity', title="Alert Severity Distribution")
        st.plotly_chart(fig1)
    with col2:
        cat_sev = df.groupby(['Label1', 'ALERT_SEVERITY']).size().reset_index(name='Count')
        fig2 = px.bar(cat_sev, x='Label1', y='Count', color='ALERT_SEVERITY', title="Traffic Activity vs Alert Severity", barmode='stack')
        st.plotly_chart(fig2)


    col3, col4 = st.columns(2)

    with col3:
        cat_sev = df.groupby(['Label', 'ALERT_SEVERITY']).size().reset_index(name='Count')
        fig2 = px.bar(cat_sev, x='Label', y='Count', color='ALERT_SEVERITY', title="Traffic Label vs Alert Severity", barmode='stack')
        st.plotly_chart(fig2)

        # df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        # alert_timeline = df.groupby([df['Timestamp'].dt.date, 'ALERT_SEVERITY']).size().reset_index(name='Count')
        # fig4 = px.line(alert_timeline, x='Timestamp', y='Count', color='ALERT_SEVERITY', title="Alert Trend Over Time")
        # st.plotly_chart(fig4)
    with col4:
        fig5 = px.pie(severity_count, names='Severity', values='Count', title="Proportion of Alert Severities")
        st.plotly_chart(fig5)





    # st.dataframe(df.groupby(['Label1', 'ALERT_SEVERITY']).size().unstack(fill_value=0))









    # Long Duration Flows - Threshold as a slider
    st.markdown("### Alerts: Long Duration Traffic")
    duration_threshold = st.slider("Flow Duration Threshold (ms)", min_value=50000000, max_value=100000000, step=5000000, value=70000000)
    high_duration_alerts = df[df['Flow Duration'] > duration_threshold]  # Use slider value as threshold
    fig = px.histogram(high_duration_alerts, x='Flow Duration', nbins=30,
                       color='Protocol', color_discrete_sequence=px.colors.sequential.Plasma)
    fig.update_layout(title=f"Suspicious Long Duration Flows (Threshold: {duration_threshold} ms)", height=400)
    st.plotly_chart(fig, use_container_width=True)


    # High Traffic IPs - Threshold as a slider
    st.markdown("### Alerts: High Traffic from Specific IPs")
    traffic_threshold = st.slider("Flow Bytes/s Threshold (bytes/s)", min_value=500000, max_value=100000000, step=50000, value=10000000)
    high_traffic_alerts = df[df['Flow Bytes/s'] > traffic_threshold]  # Use slider value as threshold
    top_ips_traffic = high_traffic_alerts['Src IP'].value_counts().nlargest(10).reset_index()
    top_ips_traffic.columns = ['Src IP', 'Alert Count']

    fig = px.bar(top_ips_traffic, x='Src IP', y='Alert Count', color='Src IP', 
                 text=top_ips_traffic['Alert Count'].apply(lambda x: f"{x/1000:.1f}K" if x > 1000 else str(x)),
                 color_discrete_sequence=px.colors.qualitative.Set2)
    fig.update_traces(textposition='outside')
    fig.update_layout(height=400, title=f"High Traffic Source IPs (Threshold: {traffic_threshold} bytes/s)")
    st.plotly_chart(fig, use_container_width=True)

    # Suspicious Traffic based on Total Packet Length
    st.markdown("### Suspicious Traffic: High Total Packet Length")
    high_packet_length = df[df['Total Length of Fwd Packet'] > 10000]  # You can adjust this threshold
    fig = px.scatter(high_packet_length, x='Src IP', y='Total Length of Fwd Packet', color='Protocol', 
                     size='Flow Duration', color_continuous_scale='Viridis')
    fig.update_layout(title="Suspicious Traffic: High Total Packet Length", height=400)
    st.plotly_chart(fig, use_container_width=True)



    st.markdown("### ⚠️ Alerts by Activity Type (Label)")
    activity_alerts = df['Label'].value_counts().reset_index()
    activity_alerts.columns = ['Activity Type', 'Alert Count']

    fig = px.bar(activity_alerts, x='Activity Type', y='Alert Count',
                 text=activity_alerts['Alert Count'].apply(lambda x: f"{x/1000:.1f}K" if x > 1000 else str(x)),
                 color='Activity Type', color_discrete_sequence=px.colors.qualitative.Plotly)
    fig.update_traces(textposition='outside')
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)



    st.markdown("### 🔌 Alerts by Protocol")
    protocol_alerts = df.groupby(['Protocol', 'Label1']).size().reset_index(name='Count')
    fig = px.bar(protocol_alerts, x='Protocol', y='Count', color='Label1',
                 text='Count', barmode='group', color_discrete_sequence=px.colors.qualitative.Prism)
    fig.update_traces(textposition='outside')
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)


    st.markdown("### 💣 Top 10 Offending IPs by Alert Type")
    top_alerts = df.groupby(['Label', 'Src IP']).size().reset_index(name='Count')
    top_alerts = top_alerts.sort_values('Count', ascending=False).head(10)

    fig = px.bar(top_alerts, x='Src IP', y='Count', color='Label',
                 text=top_alerts['Count'].apply(lambda x: f"{x/1000:.1f}K" if x > 1000 else str(x)),
                 color_discrete_sequence=px.colors.qualitative.Alphabet)
    fig.update_traces(textposition='outside')
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)


   

elif tab == "Flags":
    flags = ["FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count"]
    for flag in flags:
        fig = px.histogram(df, x=flag, title=f"{flag}")
        st.plotly_chart(fig, use_container_width=True)

elif tab == "Timing":
    fig1 = px.box(df, y="Idle Mean", title="Idle Mean")
    fig2 = px.box(df, y="Active Mean", title="Active Mean")
    st.plotly_chart(fig1, use_container_width=True)
    st.plotly_chart(fig2, use_container_width=True)






# def assign_priority(row):
#     if row["Dst Port"] == 4444 or "Botnet" in row["Label"]:
#         return "HIGH"
#     elif row["Flow Bytes/s"] > 10000:
#         return "MEDIUM"
#     else:
#         return "LOW"

# df["Alert Priority"] = df.apply(assign_priority, axis=1)

# st.subheader("2. Rule-Based Alert Prioritization")
# st.dataframe(df[["Dst Port", "Flow Bytes/s", "Label", "Alert Priority"]].head(10))

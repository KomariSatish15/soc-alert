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

st.set_page_config(page_title="SOC Framework for Network Traffic Analysis and Threat Detection", layout="wide")

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0f1c2e;
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# Load the dataset
@st.cache_data(ttl=36)
def load_data():
    data = pd.read_csv('network_traffic.csv')
    data['startDate'] = pd.to_datetime(data['startDate'])
    data['endDate'] = pd.to_datetime(data['endDate'])
    data['session_duration'] = (data['endDate'] - data['startDate']).dt.total_seconds()
    data['packet_to_byte_ratio'] = data['sPackets'] / data['sBytesSum']
    return data

st.title("Network Traffic Analysis & Threat Detection")

# 📌 *Streamlit App with Tabs*
tab1, tab2 = st.tabs(["⚡ Monitoring Dashboard", "🛡 Cybersecurity & Attack Analysis"])

with tab1:

    df = load_data()

    st.subheader("Sample Data")

    st.dataframe(df.head())

  
    with st.container():
        col1, col2 = st.columns(2, gap="small")
        col3, col4 = st.columns(2, gap="small")

        # Chart 1: Histogram (Session Duration Distribution)
        with col1:
            fig1 = px.histogram(df, x="session_duration", nbins=50, 
                                title="Session Duration Distribution", 
                                labels={"session_duration": "Duration (Seconds)"})
            fig1.update_xaxes(tickmode="linear")
            st.plotly_chart(fig1, use_container_width=True)

        # Chart 2: Scatter Plot (Bytes Sent vs. Packets Sent)
        with col2:
            fig2 = px.scatter(df, x="sPackets", y="sBytesSum", 
                              title="Bytes Sent vs. Packets Sent", 
                              labels={"sPackets": "Packets Sent", "sBytesSum": "Bytes Sent"})
            st.plotly_chart(fig2, use_container_width=True)

        # Chart 3: Line Chart (Bytes Sent Over Time)
        with col3:
            df['Timestamp'] = pd.to_datetime(df['startDate'])  # Assuming startDate is in your dataset
            fig3 = px.line(df, x="Timestamp", y="sBytesSum", 
                           title="Total Bytes Sent Over Time", 
                           labels={"sBytesSum": "Bytes Sent", "Timestamp": "Time"})
            fig3.update_yaxes(range=[df["sBytesSum"].min(), df["sBytesSum"].max()])
            st.plotly_chart(fig3, use_container_width=True)

        # Chart 4: Bar Chart (Protocol Distribution)
        with col4:

            df_protocol = df['protocol'].value_counts().reset_index()
            df_protocol.columns = ['Protocol', 'Count']

            fig4 = px.bar(
                df_protocol, 
                x="Protocol", y="Count",
                title="Protocol Distribution",
                labels={"Protocol": "Protocol", "Count": "Count"}
            )
            st.plotly_chart(fig4, use_container_width=True)


        # Chart 5: Line Chart (Inter-packet Delay vs. Time)
        with col1:
            fig5 = px.line(df, x="Timestamp", y="sInterPacketAvg", 
                           title="Inter-packet Delay Over Time", 
                           labels={"sInterPacketAvg": "Avg Inter-packet Delay (ms)", "Timestamp": "Time"})
            fig5.update_yaxes(range=[df["sInterPacketAvg"].min(), df["sInterPacketAvg"].max()])
            st.plotly_chart(fig5, use_container_width=True)

        # Chart 6: Forecast Error (If applicable)
        with col2:
            df["Forecast Error"] = df["sBytesSum"] - df["sBytesSum"].shift(1)
            df.dropna(subset=["Forecast Error"], inplace=True)
            fig6 = px.scatter(df, x="Timestamp", y="Forecast Error", 
                              title="Forecast Error Over Time",
                              labels={"Forecast Error": "Error (Bytes)", "Timestamp": "Time"},
                              color_discrete_sequence=["#ff7f0e"])
            st.plotly_chart(fig6, use_container_width=True)

        # Chart 7: Traffic Session Length Distribution
        with col3:
            fig7 = px.histogram(df, x="session_duration", nbins=50, 
                                title="Traffic Session Length Distribution", 
                                labels={"session_duration": "Session Length (Seconds)"})
            st.plotly_chart(fig7, use_container_width=True)

        # Chart 8: Total Traffic (Sent Bytes vs. Received Bytes)
        with col4:
            # Step 1: Group and sum
            total_traffic = df.groupby("Timestamp")[["sBytesSum", "rBytesSum"]].sum().reset_index()

            # Step 2: Melt to long form
            total_traffic_long = total_traffic.melt(id_vars=["Timestamp"], 
                                                    value_vars=["sBytesSum", "rBytesSum"],
                                                    var_name="Type", value_name="Bytes")

            # Step 3: Plot
            fig8 = px.bar(
                total_traffic_long, 
                x="Timestamp", y="Bytes", 
                color="Type",
                title="Total Sent vs. Received Bytes",
                labels={"Timestamp": "Time", "Bytes": "Bytes"},
                barmode="group",
                color_discrete_map={"sBytesSum": "#fa7a5f", "rBytesSum": "#89fa5f"}
            )
            st.plotly_chart(fig8, use_container_width=True)


        

    with st.container():
        col1, col2 = st.columns(2, gap="small")
        col3, col4 = st.columns(2, gap="small")

        # Chart 1: Line Chart (Packets Received Over Time)
        with col1:
            fig1 = px.line(df, x="Timestamp", y="rPackets", 
                           title="Packets Received Over Time", 
                           labels={"rPackets": "Packets Received", "Timestamp": "Time"})
            fig1.update_yaxes(range=[df["rPackets"].min(), df["rPackets"].max()])
            st.plotly_chart(fig1, use_container_width=True)

        # Chart 2: Bar Chart (Traffic by Source IP)
        with col2:
            ip_traffic = df['sIPs'].value_counts().reset_index().head(10)
            ip_traffic.columns = ['Source IP', 'Traffic Volume']

            fig2 = px.bar(
                ip_traffic, 
                x="Source IP", y="Traffic Volume", 
                title="Top 10 Source IPs by Traffic Volume",
                labels={"Source IP": "Source IP", "Traffic Volume": "Traffic Volume"}
            )
            st.plotly_chart(fig2, use_container_width=True)


        # Chart 3: Heatmap (Correlation Between Traffic Variables)
        with col3:
            correlation_matrix = df[["sBytesSum", "rBytesSum", "sPackets", "rPackets", "session_duration"]].corr()
            fig3 = px.imshow(correlation_matrix, text_auto=True, 
                             title="Correlation Between Traffic Variables")
            st.plotly_chart(fig3, use_container_width=True)

        # Chart 4: Line Chart (Received Bytes vs. Session Duration)
        with col4:
            fig4 = px.line(df, x="session_duration", y="rBytesSum", 
                           title="Received Bytes vs. Session Duration", 
                           labels={"rBytesSum": "Bytes Received", "session_duration": "Session Duration"})
            fig4.update_yaxes(range=[df["rBytesSum"].min(), df["rBytesSum"].max()])
            st.plotly_chart(fig4, use_container_width=True)

        # Chart 5: Bar Chart (Top 10 Destination IPs by Traffic)
        with col1:
            dest_ip_traffic = df['rIPs'].value_counts().reset_index().head(10)
            dest_ip_traffic.columns = ['Destination IP', 'Traffic Volume']

            fig5 = px.bar(
                dest_ip_traffic,
                x="Destination IP", y="Traffic Volume",
                title="Top 10 Destination IPs by Traffic Volume",
                labels={"Destination IP": "Destination IP", "Traffic Volume": "Traffic Volume"}
            )
            st.plotly_chart(fig5, use_container_width=True)


        # Chart 6: Line Chart (Inter-packet Delay vs. Traffic Volume)
        with col2:
            fig6 = px.line(df, x="sInterPacketAvg", y="sBytesSum", 
                           title="Inter-packet Delay vs. Traffic Volume", 
                           labels={"sInterPacketAvg": "Avg Inter-packet Delay (ms)", "sBytesSum": "Bytes Sent"})
            fig6.update_yaxes(range=[df["sBytesSum"].min(), df["sBytesSum"].max()])
            st.plotly_chart(fig6, use_container_width=True)

        # Chart 7: Bar Chart (Session Duration by Source IP)
        with col3:
            session_duration_ip = (
                df.groupby('sIPs')['session_duration']
                .mean()
                .reset_index()
                .sort_values('session_duration', ascending=False)
                .head(10)
            )

            # Optional: Rename to make things super clear
            session_duration_ip.columns = ['Source IP', 'Average Session Duration (Seconds)']

            fig7 = px.bar(
                session_duration_ip,
                x="Source IP", y="Average Session Duration (Seconds)",
                title="Top 10 Source IPs by Average Session Duration",
                labels={
                    "Source IP": "Source IP",
                    "Average Session Duration (Seconds)": "Average Session Duration (Seconds)"
                }
            )
            st.plotly_chart(fig7, use_container_width=True)


        # Chart 8: Histogram (Session Duration vs. Packets Sent)
        with col4:
            fig8 = px.histogram(df, x="session_duration", y="sPackets", 
                                title="Session Duration vs. Packets Sent", 
                                labels={"session_duration": "Session Duration (Seconds)", "sPackets": "Packets Sent"})
            st.plotly_chart(fig8, use_container_width=True)

        

    with st.container():
        col1, col2 = st.columns(2, gap="small")
        col3, col4 = st.columns(2, gap="small")

        # Chart 1: Top 10 Source MAC Addresses (sMACs)
        with col1:
            smac_traffic = df['sMACs'].value_counts().reset_index().head(10)
            smac_traffic.columns = ['Source MAC Address', 'Traffic Volume']

            fig1 = px.bar(
                smac_traffic,
                x="Source MAC Address", y="Traffic Volume",
                title="Top 10 Source MAC Addresses by Traffic Volume",
                labels={
                    "Source MAC Address": "Source MAC Address",
                    "Traffic Volume": "Traffic Volume"
                }
            )
            st.plotly_chart(fig1, use_container_width=True)


        # Chart 2: Top 10 Destination MAC Addresses (rMACs)
        with col2:
            rmac_traffic = df['rMACs'].value_counts().reset_index().head(10)
            rmac_traffic.columns = ['Destination MAC Address', 'Traffic Volume']

            fig2 = px.bar(
                rmac_traffic,
                x="Destination MAC Address", y="Traffic Volume",
                title="Top 10 Destination MAC Addresses by Traffic Volume",
                labels={
                    "Destination MAC Address": "Destination MAC Address",
                    "Traffic Volume": "Traffic Volume"
                }
            )
            st.plotly_chart(fig2, use_container_width=True)


        
    with st.container():
        col1, col2 = st.columns(2, gap="small")

        # Chart 1: Top 10 Protocols (Pie Chart)
        with col1:
            protocol_traffic = df['protocol'].value_counts().reset_index().head(10)
            protocol_traffic.columns = ['protocol', 'count']  # Rename columns for clarity
            fig1 = px.pie(protocol_traffic, names="protocol", values="count", 
                          title="Top 10 Protocols by Traffic Volume",
                          labels={"protocol": "Protocol", "count": "Traffic Volume"})
            st.plotly_chart(fig1, use_container_width=True)


        # Chart 2: NST_M_Label (Pie Chart)
        with col2:
            nst_m_label_traffic = df['NST_M_Label'].value_counts().reset_index()
            nst_m_label_traffic.columns = ['NST_M_Label', 'count']  # Rename columns
            fig2 = px.pie(nst_m_label_traffic, names="NST_M_Label", values="count", 
                          title="NST_M_Label Distribution",
                          labels={"NST_M_Label": "NST_M_Label", "count": "Count"})
            st.plotly_chart(fig2, use_container_width=True)



        df = df.dropna()

    with st.container():
        col1, col2 = st.columns(2, gap="small")
        col3, col4 = st.columns(2, gap="small")

        # Distribution: sPackets
        with col1:
            fig1 = px.histogram(df, x="sPackets", nbins=50, title="Distribution of sPackets", 
                                 labels={"sPackets": "sPackets"})
            st.plotly_chart(fig1, use_container_width=True)

        # Distribution: rPackets
        with col2:
            fig2 = px.histogram(df, x="rPackets", nbins=50, title="Distribution of rPackets", 
                                 labels={"rPackets": "rPackets"})
            st.plotly_chart(fig2, use_container_width=True)

        # Distribution: sBytesSum
        with col3:
            fig3 = px.histogram(df, x="sBytesSum", nbins=50, title="Distribution of sBytesSum", 
                                 labels={"sBytesSum": "sBytesSum"})
            st.plotly_chart(fig3, use_container_width=True)

        # Distribution: rBytesSum
        with col4:
            fig4 = px.histogram(df, x="rBytesSum", nbins=50, title="Distribution of rBytesSum", 
                                 labels={"rBytesSum": "rBytesSum"})
            st.plotly_chart(fig4, use_container_width=True)

    with st.container():
        col5, col6 = st.columns(2, gap="small")
        col7, col8 = st.columns(2, gap="small")

        # Distribution: sBytesMax
        with col5:
            fig5 = px.histogram(df, x="sBytesMax", nbins=50, title="Distribution of sBytesMax", 
                                 labels={"sBytesMax": "sBytesMax"})
            st.plotly_chart(fig5, use_container_width=True)

        # Distribution: rBytesMax
        with col6:
            fig6 = px.histogram(df, x="rBytesMax", nbins=50, title="Distribution of rBytesMax", 
                                 labels={"rBytesMax": "rBytesMax"})
            st.plotly_chart(fig6, use_container_width=True)

        # Distribution: sBytesMin
        with col7:
            fig7 = px.histogram(df, x="sBytesMin", nbins=50, title="Distribution of sBytesMin", 
                                 labels={"sBytesMin": "sBytesMin"})
            st.plotly_chart(fig7, use_container_width=True)

        # Distribution: rBytesMin
        with col8:
            fig8 = px.histogram(df, x="rBytesMin", nbins=50, title="Distribution of rBytesMin", 
                                 labels={"rBytesMin": "rBytesMin"})
            st.plotly_chart(fig8, use_container_width=True)

    with st.container():
        col9, col10 = st.columns(2, gap="small")
        col11, col12 = st.columns(2, gap="small")

        # Distribution: sBytesAvg
        with col9:
            fig9 = px.histogram(df, x="sBytesAvg", nbins=50, title="Distribution of sBytesAvg", 
                                 labels={"sBytesAvg": "sBytesAvg"})
            st.plotly_chart(fig9, use_container_width=True)

        # Distribution: rBytesAvg
        with col10:
            fig10 = px.histogram(df, x="rBytesAvg", nbins=50, title="Distribution of rBytesAvg", 
                                  labels={"rBytesAvg": "rBytesAvg"})
            st.plotly_chart(fig10, use_container_width=True)

        # Distribution: sLoad
        with col11:
            fig11 = px.histogram(df, x="sLoad", nbins=50, title="Distribution of sLoad", 
                                 labels={"sLoad": "sLoad"})
            st.plotly_chart(fig11, use_container_width=True)

        # Distribution: rLoad
        with col12:
            fig12 = px.histogram(df, x="rLoad", nbins=50, title="Distribution of rLoad", 
                                 labels={"rLoad": "rLoad"})
            st.plotly_chart(fig12, use_container_width=True)

    with st.container():
        col13, col14 = st.columns(2, gap="small")
        col15, col16 = st.columns(2, gap="small")

        # Distribution: sPayloadSum
        with col13:
            fig13 = px.histogram(df, x="sPayloadSum", nbins=50, title="Distribution of sPayloadSum", 
                                 labels={"sPayloadSum": "sPayloadSum"})
            st.plotly_chart(fig13, use_container_width=True)

        # Distribution: rPayloadSum
        with col14:
            fig14 = px.histogram(df, x="rPayloadSum", nbins=50, title="Distribution of rPayloadSum", 
                                 labels={"rPayloadSum": "rPayloadSum"})
            st.plotly_chart(fig14, use_container_width=True)

        # Distribution: sPayloadMax
        with col15:
            fig15 = px.histogram(df, x="sPayloadMax", nbins=50, title="Distribution of sPayloadMax", 
                                 labels={"sPayloadMax": "sPayloadMax"})
            st.plotly_chart(fig15, use_container_width=True)

        # Distribution: rPayloadMax
        with col16:
            fig16 = px.histogram(df, x="rPayloadMax", nbins=50, title="Distribution of rPayloadMax", 
                                 labels={"rPayloadMax": "rPayloadMax"})
            st.plotly_chart(fig16, use_container_width=True)

    with st.container():
        col17, col18 = st.columns(2, gap="small")
        col19, col20 = st.columns(2, gap="small")

        # Distribution: sPayloadMin
        with col17:
            fig17 = px.histogram(df, x="sPayloadMin", nbins=50, title="Distribution of sPayloadMin", 
                                 labels={"sPayloadMin": "sPayloadMin"})
            st.plotly_chart(fig17, use_container_width=True)

        # Distribution: rPayloadMin
        with col18:
            fig18 = px.histogram(df, x="rPayloadMin", nbins=50, title="Distribution of rPayloadMin", 
                                 labels={"rPayloadMin": "rPayloadMin"})
            st.plotly_chart(fig18, use_container_width=True)

        # Distribution: sPayloadAvg
        with col19:
            fig19 = px.histogram(df, x="sPayloadAvg", nbins=50, title="Distribution of sPayloadAvg", 
                                 labels={"sPayloadAvg": "sPayloadAvg"})
            st.plotly_chart(fig19, use_container_width=True)

        # Distribution: rPayloadAvg
        with col20:
            fig20 = px.histogram(df, x="rPayloadAvg", nbins=50, title="Distribution of rPayloadAvg", 
                                 labels={"rPayloadAvg": "rPayloadAvg"})
            st.plotly_chart(fig20, use_container_width=True)

    with st.container():
        col21, col22 = st.columns(2, gap="small")
        # Distribution: sInterPacketAvg
        with col21:
            fig21 = px.histogram(df, x="sInterPacketAvg", nbins=50, title="Distribution of sInterPacketAvg", 
                                 labels={"sInterPacketAvg": "sInterPacketAvg"})
            st.plotly_chart(fig21, use_container_width=True)

        # Distribution: rInterPacketAvg
        with col22:
            fig22 = px.histogram(df, x="rInterPacketAvg", nbins=50, title="Distribution of rInterPacketAvg", 
                                 labels={"rInterPacketAvg": "rInterPacketAvg"})
            st.plotly_chart(fig22, use_container_width=True)

with tab2:
    df = load_data()

    # Ensure the Timestamp is in datetime format
    df['startDate'] = pd.to_datetime(df['startDate'])
    df['endDate'] = pd.to_datetime(df['endDate'])

    # Preprocess the data: Handle missing values
    df.fillna(0, inplace=True)

    # Feature selection for anomaly detection
    X = df[['sPackets', 'rPackets', 'sBytesSum', 'rBytesSum', 'sLoad', 'rLoad']]

    # Dynamic slider for Anomaly Contamination
    anomaly_contamination = st.slider(
        "🤖 Set Anomaly Contamination Rate (Isolation Forest)",
        0.001, 0.05, 0.01, step=0.005
    )

    # Train Isolation Forest model for anomaly detection with dynamic contamination rate
    iso_forest = IsolationForest(contamination=anomaly_contamination)
    df['anomaly_iso'] = iso_forest.fit_predict(X)
    anomalies_iso = df[df['anomaly_iso'] == -1]

    # 1. Real-time Anomaly Count & Alert System
    st.write(f"*Total Anomalies Detected:* {len(anomalies_iso) }")
    if len(anomalies_iso) > 1500:
        st.warning("High number of anomalies detected!")
    else:
        st.success("Anomalies count is within expected range.")


    fig_iso = px.scatter(
        anomalies_iso, x='startDate', y='sBytesSum', color='sIPs',
        title="Anomalies (Isolation Forest)"
    )
    st.plotly_chart(fig_iso, use_container_width=True)

    
    # 2. Anomaly Trend Over Time (Time Series Plot)
    fig_time_iso = px.line(
        anomalies_iso, x='startDate', y='sBytesSum', color='sIPs',
        title="Anomalies Trend (Isolation Forest)"
    )
    st.plotly_chart(fig_time_iso, use_container_width=True)

    
    # 4. Correlation Matrix of Features
    corr_matrix = X.corr()
    fig_corr = px.imshow(corr_matrix, title="Feature Correlation Matrix")
    st.plotly_chart(fig_corr, use_container_width=True)

    
    # 6. Boxplot for Outlier Detection
    fig_box = px.box(df, y="sBytesSum", title="Boxplot for sBytesSum", points='all')
    st.plotly_chart(fig_box, use_container_width=True)


    # 8. Feature Threshold Alerts (Manual Inspection)
    threshold = 10000
    high_sBytes = df[df['sBytesSum'] > threshold]
    if not high_sBytes.empty:
        st.warning(f"Found {len(high_sBytes)} entries with sBytesSum greater than {threshold}")

    # 9. Advanced Alerts (Email/Push Notification - Placeholder)
    # Uncomment and implement below if you want to send an email in case of high anomaly count
    def send_alert_email():
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login("your_email@gmail.com", "your_password")
                message = "Subject: Anomaly Alert\n\nHigh anomaly count detected."
                server.sendmail("your_email@gmail.com", "recipient_email@gmail.com", message)
        except Exception as e:
            st.error(f"Error sending email: {e}")
    
    if len(anomalies_iso) > 2000:
        send_alert_email()

    # 10. Anomaly Summary (Top Anomalies)
    st.write("*Top 5 Anomalies Detected (by Isolation Forest):*")
    st.dataframe(anomalies_iso[['sIPs', 'sBytesSum', 'startDate']].head())


    with st.container():

        # Time-of-Day and Day-of-Week Heatmap
        st.markdown("### 🔥 Anomaly Heatmap by Time & Day")
        anomalies_iso['hour'] = anomalies_iso['startDate'].dt.hour
        anomalies_iso['weekday'] = anomalies_iso['startDate'].dt.day_name()
        heatmap_data = anomalies_iso.groupby(['weekday', 'hour']).size().unstack().fillna(0)
        st.dataframe(heatmap_data)


        # Top Talkers Bar Chart
        st.markdown("### 💡 Top Talkers by Average Sent Bytes")
        top_senders = df.groupby('sIPs')['sBytesSum'].mean().sort_values(ascending=False).head(10)
        st.bar_chart(top_senders)


        st.markdown("### 📉 Feature Distribution: Anomalies vs Normal")

        # Prepare data
        anomaly_data = df[df['anomaly_iso'] == -1]['sBytesSum']
        normal_data = df[df['anomaly_iso'] == 1]['sBytesSum']

        # Generate KDE manually using scipy
        x_vals = np.linspace(min(df['sBytesSum']), max(df['sBytesSum']), 100)

        kde_anomaly = gaussian_kde(anomaly_data)(x_vals)
        kde_normal = gaussian_kde(normal_data)(x_vals)

        # Create Plotly figure
        fig_dist = go.Figure()

        fig_dist.add_trace(go.Scatter(
            x=x_vals, y=kde_anomaly, fill='tozeroy', mode='lines',
            name='Anomalies', line=dict(color='red')
        ))

        fig_dist.add_trace(go.Scatter(
            x=x_vals, y=kde_normal, fill='tozeroy', mode='lines',
            name='Normal', line=dict(color='green')
        ))

        fig_dist.update_layout(
            title="sBytesSum Distribution: Anomalies vs Normal",
            xaxis_title="sBytesSum",
            yaxis_title="Density",
            legend_title="Legend",
            template="plotly_dark"
        )

        st.plotly_chart(fig_dist, use_container_width=True)


    
        # Rolling Window Anomaly Rate
        st.markdown("### ⏱ Rolling Anomaly Rate (1 Hour)")
        df['is_anomaly'] = (df['anomaly_iso'] == -1).astype(int)
        df_sorted = df.sort_values("startDate")
        df_sorted['anomaly_rate_rolling'] = (
            df_sorted.set_index('startDate')['is_anomaly']
            .rolling('1H')
            .mean()
            .reset_index(drop=True)
        )
        fig_roll = px.line(df_sorted, x='startDate', y='anomaly_rate_rolling', title="Rolling Anomaly Rate (1 Hour)")
        st.plotly_chart(fig_roll, use_container_width=True)


        # Auto Severity Score
        st.markdown("### 🚨 Auto Severity Classification for Anomalies")
        def calculate_severity(row):
            if row['sBytesSum'] > 20000 or row['sLoad'] > 0.8:
                return "High"
            elif row['sBytesSum'] > 10000:
                return "Medium"
            else:
                return "Low"
        anomalies_iso['severity'] = anomalies_iso.apply(calculate_severity, axis=1)
        st.dataframe(anomalies_iso[['sIPs', 'sBytesSum', 'sLoad', 'severity']].sort_values(by='severity', ascending=False))

        
        # IP Lookup Tool
        st.markdown("### 🕵 Investigate Specific Source IP")
        ip_input = st.text_input("Enter Source IP to Inspect:")
        if ip_input:
            st.dataframe(df[df['sIPs'] == ip_input])

    with st.container():
        st.markdown("### 🧭 Radar Chart: Feature Profile")

        # Get all numeric columns except the label
        numeric_cols = df.select_dtypes(include='number').columns.tolist()
        candidate_features = [col for col in numeric_cols if col != 'anomaly_iso']

        if len(candidate_features) >= 2:
            from sklearn.preprocessing import MinMaxScaler
            import plotly.graph_objects as go

            radar_df = df[candidate_features + ['anomaly_iso']].dropna().copy()
            scaler = MinMaxScaler()
            radar_scaled = scaler.fit_transform(radar_df[candidate_features])
            radar_scaled_df = pd.DataFrame(radar_scaled, columns=candidate_features)

            # Choose one anomaly and one normal
            anomaly = radar_scaled_df[df['anomaly_iso'] == -1].head(1)
            normal = radar_scaled_df[df['anomaly_iso'] == 1].head(1)

            if not anomaly.empty and not normal.empty:
                radar_plot_df = pd.concat([anomaly, normal])
                labels = list(radar_plot_df.columns)
                values = radar_plot_df.values

                fig = go.Figure()
                fig.add_trace(go.Scatterpolar(r=values[0], theta=labels, fill='toself', name='Anomaly'))
                fig.add_trace(go.Scatterpolar(r=values[1], theta=labels, fill='toself', name='Normal'))
                fig.update_layout(polar=dict(radialaxis=dict(visible=True)), showlegend=True)
                st.plotly_chart(fig)
            else:
                st.info("Not enough anomaly or normal data for Radar Chart.")
        else:
            st.info("Not enough numeric features for Radar Chart.")

    
  
    with st.container():
        st.markdown("### 🌐 Sankey Diagram: Traffic Flow")

        # Minimal working example — aggregate traffic flows
        sankey_data = df.groupby(['sIPs', 'rIPs'])['sBytesSum'].sum().reset_index()

        if len(sankey_data) > 0:
            all_nodes = list(set(sankey_data['sIPs']) | set(sankey_data['rIPs']))
            node_map = {ip: i for i, ip in enumerate(all_nodes)}

            sources = sankey_data['sIPs'].map(node_map)
            targets = sankey_data['rIPs'].map(node_map)
            values = sankey_data['sBytesSum']

            fig = go.Figure(data=[go.Sankey(
                node=dict(label=all_nodes),
                link=dict(source=sources, target=targets, value=values)
            )])

            st.plotly_chart(fig)
        else:
            st.info("No data available to create Sankey Diagram.")

    # -------------------------------------


    edge_attr = 'weight' if 'weight' in df.columns else None

    # Create a container for the network graph
    with st.container():
        st.markdown("### 🕸 Interactive Network Graph")

        # Create a network graph using NetworkX
        if edge_attr:
            G = nx.from_pandas_edgelist(df, source='sIPs', target='rIPs', edge_attr=edge_attr)
        else:
            G = nx.from_pandas_edgelist(df, source='sIPs', target='rIPs')

        # Initialize Pyvis Network for interactive graph
        net = Network(height="600px", width="100%", notebook=True)
        net.from_nx(G)

        # Customize the layout and appearance if needed
        net.set_options("""
        var options = {
            "physics": {
                "enabled": true,
                "barnesHut": {
                    "gravitationalConstant": -8000,
                    "springLength": 150
                }
            },
            "nodes": {
                "color": {
                    "background": "skyblue",
                    "border": "gray"
                },
                "size": 20
            },
            "edges": {
                "color": "gray",
                "width": 1
            }
        }
        """)

        # Generate the interactive HTML file for the network graph
        net.show("network_graph.html")

        # Render the graph in the Streamlit app
        HtmlFile = open("network_graph.html", 'r', encoding='utf-8')
        st.components.v1.html(HtmlFile.read(), height=600)









 

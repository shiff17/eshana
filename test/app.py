import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.cluster import KMeans

# -------------------- VISUALIZATION FUNCTION --------------------
def ml_visualizations(df, before_df=None):
    st.header("📊 ML-Based Vulnerability Insights & Visualizations")

    # Severity numeric mapping for ML
    if "severity" in df.columns:
        sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        df["severity_num"] = df["severity"].map(sev_map).fillna(0)

    vis_type = st.selectbox(
        "Choose visualization",
        ["Severity (Bar)", "Severity (Line)", "Vulnerability Pie",
         "Scatter Severity", "Heatmap", "Histogram", "Boxplot", "All"]
    )

    # ---------------- BAR ----------------
    if vis_type in ["Severity (Bar)", "All"] and "severity" in df.columns:
        counts = df["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        fig = px.bar(counts, x="Severity", y="Count", text="Count", color="Severity",
                     title="Vulnerabilities by Severity")
        st.plotly_chart(fig, use_container_width=True)

    # ---------------- LINE ----------------
    if vis_type in ["Severity (Line)", "All"] and "severity" in df.columns:
        counts = df["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        fig = px.line(counts, x="Severity", y="Count", markers=True,
                      title="Trend of Vulnerabilities by Severity")
        st.plotly_chart(fig, use_container_width=True)

    # ---------------- PIE ----------------
    if vis_type in ["Vulnerability Pie", "All"] and "status" in df.columns:
        counts = df["status"].value_counts().reset_index()
        counts.columns = ["Status", "Count"]
        fig = px.pie(counts, values="Count", names="Status", title="Vulnerability Status Distribution")
        st.plotly_chart(fig, use_container_width=True)

    # ---------------- SCATTER ----------------
    if vis_type in ["Scatter Severity", "All"] and "severity_num" in df.columns:
        fig = px.scatter(df, x=np.arange(len(df)), y="severity_num", color="status",
                         labels={"severity_num": "Severity Level"},
                         title="Scatter Plot of Vulnerabilities")
        st.plotly_chart(fig, use_container_width=True)

    # ---------------- HEATMAP ----------------
    if vis_type in ["Heatmap", "All"] and "severity_num" in df.columns:
        corr = df[["severity_num"]].corr()
        fig = px.imshow(corr, text_auto=True, title="Correlation Heatmap (Severity)")
        st.plotly_chart(fig, use_container_width=True)

    # ---------------- HISTOGRAM ----------------
    if vis_type in ["Histogram", "All"] and "severity" in df.columns:
        fig = px.histogram(df, x="severity", color="status", barmode="group",
                           title="Severity Distribution Histogram")
        st.plotly_chart(fig, use_container_width=True)

    # ---------------- BOXPLOT ----------------
    if vis_type in ["Boxplot", "All"] and "severity_num" in df.columns:
        fig = px.box(df, y="severity_num", color="status",
                     labels={"severity_num": "Severity Level"},
                     title="Boxplot of Severity Levels")
        st.plotly_chart(fig, use_container_width=True)


# -------------------- NAVIGATION --------------------
st.sidebar.title("🛡 MESS")
page = st.sidebar.radio(
    "Navigate",
    ["Homepage", "Analytics", "Visualization"]
)

# -------------------- HOMEPAGE --------------------
if page == "Homepage":
    st.title("🛡 MESS: Machine-driven Exploit Shielding System")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)

        st.subheader("📌 Raw Data (Before Cleaning)")
        st.dataframe(df, use_container_width=True)

        # Save before snapshot
        before_snapshot = df.copy()
        before_len = len(df)

        # Cleaning: drop null values
        df = df.dropna()
        after_len = len(df)

        # Accuracy improvement
        if before_len > 0:
            improvement = (after_len / before_len) * 100
            st.info(f"✅ Data cleaned successfully. Approx. {improvement:.2f}% data retained → improved accuracy of analysis.")

            # -------------------- GAUGE CHART --------------------
            fig_gauge = px.pie(
                values=[improvement, 100 - improvement],
                names=["Retained", "Dropped"],
                hole=0.6,
                title="Data Retention Accuracy",
                color=["Retained", "Dropped"],
                color_discrete_map={"Retained": "#2a9d8f", "Dropped": "#e63946"}
            )
            fig_gauge.update_traces(textinfo="label+percent", pull=[0.05, 0])
            st.plotly_chart(fig_gauge, use_container_width=True)

            # Data volume chart
            acc_df = pd.DataFrame({
                "Stage": ["Before", "After"],
                "Rows": [before_len, after_len]
            })
            fig_acc = px.bar(acc_df, x="Stage", y="Rows", text="Rows",
                             title="📊 Data Volume Before vs After Cleaning",
                             color="Stage")
            st.plotly_chart(fig_acc, use_container_width=True)

        # Clustering example
        if "severity" in df.columns:
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)
            km = KMeans(n_clusters=2, random_state=42, n_init=10)
            df["cluster"] = km.fit_predict(df[["severity_num"]])

        # Simulate patching
        if "status" in df.columns:
            df["status"] = df["status"].replace("Vulnerable", "Safe")

        st.subheader("✨ Processed Data (After Cleaning & Self-Healing)")
        st.dataframe(df, use_container_width=True)

        # -------------------- DONUT CHART --------------------
        if "status" in df.columns:
            st.subheader("🍩 Vulnerability Status (Donut Chart)")
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["Status", "Count"]

            fig_donut = px.pie(
                status_counts,
                values="Count",
                names="Status",
                hole=0.5,
                title="Vulnerability Status Breakdown (After Cleaning)",
                color="Status",
                color_discrete_map={"Vulnerable": "#e63946", "Safe": "#2a9d8f"}
            )
            fig_donut.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(fig_donut, use_container_width=True)

        # Download
        st.download_button(
            label="📥 Download Processed Data",
            data=df.to_csv(index=False),
            file_name="processed_results.csv",
            mime="text/csv"
        )

        # -------------------- BEFORE VS AFTER --------------------
        st.subheader("🔍 Before vs After (Graphical Comparison)")
        if "severity" in before_snapshot.columns and "severity" in df.columns:
            before_counts = before_snapshot["severity"].value_counts().reset_index()
            before_counts.columns = ["Severity", "Count"]

            after_counts = df["severity"].value_counts().reset_index()
            after_counts.columns = ["Severity", "Count"]

            col1, col2 = st.columns(2)
            with col1:
                fig_before = px.bar(before_counts, x="Severity", y="Count", text="Count",
                                    color="Severity", title="Before Cleaning & Patching")
                st.plotly_chart(fig_before, use_container_width=True)

            with col2:
                fig_after = px.bar(after_counts, x="Severity", y="Count", text="Count",
                                   color="Severity", title="After Cleaning & Patching")
                st.plotly_chart(fig_after, use_container_width=True)

# -------------------- ANALYTICS --------------------
elif page == "Analytics":
    st.title("📊 MESS Analytics & Recommendations")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)
        before_len = len(df)
        df = df.dropna()
        after_len = le_

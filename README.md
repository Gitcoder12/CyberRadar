🛡️ CyberRadar
Real-time vulnerability intelligence and risk prioritization.


CyberRadar aggregates CVE data from NVD, CISA KEV, and FIRST EPSS to identify and prioritize actively exploited and high-risk vulnerabilities.

Traditional scanners rely purely on CVSS severity scores, which leads to alert fatigue. CyberRadar solves this by calculating a dynamic Composite Risk Score that factors in real-world exploitation probability.

🚀 Features
Live Threat Intelligence: Aggregates data from NVD (National Vulnerability Database), CISA KEV (Known Exploited Vulnerabilities), and FIRST EPSS.

Composite Risk Engine: Weighs CVSS severity (40%) and EPSS probability (60%) to prioritize actual threats over theoretical ones.

KEV Prioritization: Actively exploited CVEs are automatically escalated to a Critical risk score of 100.

Interactive SOC Dashboard: Features a Polar Threat Radar, Top Affected Vendors bar chart, and a real-time System Weakness gauge.

The "Solidifier" Protocol: Simulated automated defense logic that detects repeatedly exploited CVEs and logs WAF quarantine rules.

Resilient Architecture: Built-in API rate limiting, batching, and st.cache_data to prevent 429 errors and ensure rapid UI loads.

Exportable Reports: Filter by severity or KEV status and export the results directly to CSV.

💻 Tech Stack
Frontend: Streamlit · Plotly

Backend: Python · Requests

Data Processing: Pandas

Data Validation: Pydantic

⚙️ Setup
bash
# Clone the repository
git clone https://github.com/Gitcoder12/CyberRadar.git
cd CyberRadar

# Install dependencies
pip install -r requirements.txt

# Run the dashboard
streamlit run dashboard.py
Optional: To avoid NVD API rate limits, set your free NVD_API_KEY in a .env file or Streamlit Secrets.

🧮 Composite Risk Scoring
The risk score is calculated on a normalized 0–100 scale:

R
=
0.4
×
CVSS
+
0.6
×
EPSS
R=0.4×CVSS+0.6×EPSS

If a vulnerability is listed in CISA KEV (Known Exploited), the score is automatically forced to 100.

📄 License
This project is licensed under the MIT License.

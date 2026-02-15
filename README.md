# 🌍 GeoTrace – Internet Footprint Visualizer

GeoTrace is a cyber-style web application that analyzes a domain name, resolves its IP address, detects geolocation data, and classifies potential threat levels.

Built using Flask, SQLite, and OSINT techniques.

---

## 🔥 Live Demo
( https://geotrace-48hj.onrender.com/ )

---

## 📌 Features

- 🌐 Domain to IP Resolution
- 📍 IP Geolocation Detection
- 🧠 Threat Classification Logic
- 🗺 Interactive World Map (Leaflet + OpenStreetMap)
- 📜 Analysis History Storage (SQLite)
- ⚡ REST API Endpoint (/analyze)
- 🎯 Clean Cyber UI Design

---

## 🛠 Tech Stack

- Python 3
- Flask
- SQLite
- Requests
- Leaflet.js
- OpenStreetMap
- Gunicorn (Production Server)
- Render (Deployment)

---

## 🧠 How It Works

1. User enters a domain.
2. The system:
   - Resolves the domain to IP using `socket`
   - Fetches geolocation data via external API
   - Applies custom threat scoring logic
3. Results are:
   - Displayed on world map
   - Stored in database
   - Available in history section

---

## 🧩 Project Structure
GeoTrace/ │ ├── app.py              # Main Flask application ├── database.py         # SQLite database operations ├── threat_logic.py     # Domain classification logic ├── requirements.txt    # Python dependencies ├── templates/          # HTML files ├── static/             # CSS & JS files └── README.md


📊 Threat Classification Logic
GeoTrace assigns risk levels based on:
- Suspicious TLD patterns
- Keyword matching
- Known malicious domain patterns
- IP characteristics
Threat Levels:
- 🟢 Safe
- 🟡 Suspicious
- 🔴 High Risk



🔐 Security Notice
This project is developed for:
Educational purposes
Cybersecurity awareness
OSINT learning
It does NOT perform active attacks or intrusive scanning.



👨‍💻 Author
Abhijit Rathod
Cybersecurity Enthusiast | Python Developer | OSINT Learner
GitHub: https://github.com/Abhijit9999908�


⭐ Future Improvements
...

📜 License
This project is open-source and available under the MIT License.

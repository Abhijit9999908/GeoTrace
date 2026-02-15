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

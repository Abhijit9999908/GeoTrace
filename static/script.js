/**
 * script.js — GeoTrace Pro Logic (v3.0)
 */

const map = L.map("map").setView([20, 0], 2);
const markersLayer = L.layerGroup().addTo(map);

L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
    attribution: "GeoTrace Pro",
    maxZoom: 19,
}).addTo(map);

const domainInput = document.getElementById("domainInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const statusMsg = document.getElementById("statusMsg");
const resultCard = document.getElementById("resultCard");
const historyBody = document.getElementById("historyBody");

document.addEventListener("DOMContentLoaded", () => {
    analyzeBtn.addEventListener("click", analyzeDomain);
    loadHistory();
    
    domainInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") analyzeDomain();
    });
});

async function analyzeDomain() {
    const domain = domainInput.value.trim();
    if (!domain) return updateStatus("⚠️ Please enter a domain.", "error");

    // UI Loading State
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = 'SCANNING...';
    updateStatus("📡 Triangulating target...", "normal");

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain }),
        });

        const data = await response.json();

        // Handle Errors (including Rate Limits)
        if (!response.ok) {
            if (response.status === 429) {
                updateStatus("⚡ Rate Limit Hit. Please wait a moment.", "error");
            } else {
                updateStatus(`❌ ${data.error}`, "error");
            }
            return;
        }

        // Success
        updateStatus("✅ Target Acquired.", "success");
        renderData(data);
        updateMap(data);
        loadHistory();

    } catch (err) {
        updateStatus("⚠️ Network Error. Server unreachable.", "error");
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "INITIATE SCAN";
    }
}

function renderData(data) {
    document.getElementById("resDomain").textContent = data.domain;
    document.getElementById("resIP").textContent = data.ip_address;
    document.getElementById("resCountry").textContent = data.country;
    document.getElementById("resCoords").textContent = `${data.latitude}, ${data.longitude}`;
    
    const badge = document.getElementById("resThreat");
    badge.textContent = data.threat_level;
    
    // Clear old classes and add new one
    badge.className = "badge"; 
    badge.classList.add(data.threat_level.toLowerCase());

    resultCard.style.display = "block";
}

function updateMap(data) {
    markersLayer.clearLayers();
    const lat = data.latitude;
    const lon = data.longitude;

    const colorMap = {
        "SAFE": "#2ecc71",
        "TRACKER": "#f1c40f",
        "SUSPICIOUS": "#e67e22",
        "UNKNOWN": "#e74c3c"
    };

    const color = colorMap[data.threat_level] || "#e74c3c";

    const marker = L.circleMarker([lat, lon], {
        color: color,
        fillColor: color,
        fillOpacity: 0.8,
        radius: 12
    }).addTo(markersLayer);

    marker.bindPopup(`
        <div style="text-align:center">
            <b>${data.domain}</b><br>
            ${data.ip_address}<br>
            ${data.country}
        </div>
    `).openPopup();

    map.flyTo([lat, lon], 13, { duration: 1.5 });
}

async function loadHistory() {
    try {
        const res = await fetch("/history");
        const history = await res.json();
        
        historyBody.innerHTML = "";
        
        history.forEach(item => {
            const row = `
                <tr>
                    <td><b>${item.domain}</b></td>
                    <td class="mono">${item.ip_address}</td>
                    <td>${item.country}</td>
                    <td><span class="badge ${item.threat_level.toLowerCase()}">${item.threat_level}</span></td>
                    <td class="time">${new Date(item.timestamp).toLocaleTimeString()}</td>
                </tr>
            `;
            historyBody.insertAdjacentHTML('beforeend', row);
        });
    } catch (e) {
        console.error("History Error", e);
    }
}

function updateStatus(msg, type) {
    statusMsg.textContent = msg;
    statusMsg.className = `status-msg ${type}`;
    if (type === "success") setTimeout(() => { statusMsg.textContent = ""; }, 5000);
}

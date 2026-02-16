/**
 * script.js — GeoTrace Pro Logic (Fixed)
 */

const map = L.map("map").setView([20, 0], 2);

L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "GeoTrace",
    maxZoom: 19,
}).addTo(map);

const markersLayer = L.layerGroup().addTo(map);

// DOM Elements
const domainInput = document.getElementById("domainInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const statusMsg = document.getElementById("statusMsg");
const resultCard = document.getElementById("resultCard");
const historyBody = document.getElementById("historyBody");

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
    analyzeBtn.addEventListener("click", analyzeDomain);
    loadHistory();
    
    domainInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") analyzeDomain();
    });
});

async function analyzeDomain() {
    const domain = domainInput.value.trim();
    if (!domain) return updateStatus("⚠️ Enter a domain name.", "error");

    // Reset UI
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "SCANNING...";
    updateStatus("📡 Interrogating global nodes...", "");

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain }),
        });

        const data = await response.json();

        if (response.ok) {
            updateStatus("✅ Target Acquired.", "success");
            renderData(data);
            updateMap(data);
            loadHistory();
        } else {
            updateStatus(`❌ ${data.error}`, "error");
        }
    } catch (err) {
        console.error(err);
        updateStatus("⚠️ Connection Error. Ensure server is running.", "error");
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
    badge.className = `badge ${data.threat_level.toLowerCase()}`;

    // Make sure the result card is visible
    resultCard.style.display = "block";
}

function updateMap(data) {
    markersLayer.clearLayers();
    const lat = data.latitude;
    const lon = data.longitude;

    const marker = L.circleMarker([lat, lon], {
        color: '#6c63ff',
        fillColor: '#6c63ff',
        fillOpacity: 0.8,
        radius: 10
    }).addTo(markersLayer);

    marker.bindPopup(`<b>${data.domain}</b><br>${data.country}`).openPopup();
    map.flyTo([lat, lon], 13);
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
                    <td>${item.ip_address}</td>
                    <td>${item.country}</td>
                    <td><span class="badge ${item.threat_level.toLowerCase()}">${item.threat_level}</span></td>
                    <td style="color: #888; font-size: 0.85rem">${new Date(item.timestamp).toLocaleTimeString()}</td>
                </tr>
            `;
            historyBody.insertAdjacentHTML('beforeend', row);
        });
    } catch (e) {
        console.log("History load error", e);
    }
}

function updateStatus(msg, type) {
    statusMsg.textContent = msg;
    statusMsg.className = `status-msg ${type}`;
}

/**
 * script.js — GeoTrace Pro Logic (UPDATED)
 */

// ── Configuration ──
const MAP_ZOOM_LEVEL = 13;
const map = L.map("map", { 
    zoomSnap: 0.5, 
    scrollWheelZoom: true, 
    zoomAnimation: true 
}).setView([20, 0], 2);

L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "GeoTrace Elite",
    maxZoom: 20,
}).addTo(map);

const markersLayer = L.layerGroup().addTo(map);

const COLORS = {
    SAFE:    "#2ecc71", // Green
    TRACKER: "#f1c40f", // Yellow
    UNKNOWN: "#e74c3c", // Red
};

// ── DOM References ──
const domainInput  = document.getElementById("domainInput");
const analyzeBtn   = document.getElementById("analyzeBtn");
const statusMsg    = document.getElementById("statusMsg");
const resultCard   = document.getElementById("resultCard");
const historyBody  = document.getElementById("historyBody");

// ── Initialization ──
document.addEventListener("DOMContentLoaded", () => {
    // 1. Attach Event Listener to Button
    analyzeBtn.addEventListener("click", analyzeDomain);
    
    // 2. Load History on Page Start
    loadHistory();
    
    // 3. Allow "Enter" key to trigger analysis
    domainInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") analyzeDomain();
    });
});

// ── Analysis Logic ──
async function analyzeDomain() {
    const domain = domainInput.value.trim().toLowerCase();

    if (!domain) {
        updateStatus("⚠️ Please provide a target domain.", "error");
        return;
    }

    // UI Feedback
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span class="spinner"></span> INTERROGATING...';
    updateStatus("🔍 Tracing packets across global nodes...", "");

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain }),
        });

        const data = await response.json();

        if (!response.ok) {
            updateStatus(data.error || "Analysis Failed.", "error");
            return;
        }

        // Execution Flow
        updateStatus(`✅ Signal lock: ${data.domain}`, "success");
        renderData(data);
        animateToLocation(data);
        
        // Refresh the history table immediately
        loadHistory(); 

    } catch (err) {
        console.error(err);
        updateStatus("📡 Connection Timeout. Is the server running?", "error");
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze";
    }
}

// ── History Logic (NEW) ──
async function loadHistory() {
    try {
        const response = await fetch("/history");
        const history = await response.json();
        
        historyBody.innerHTML = ""; // Clear current table

        if (history.length === 0) {
            historyBody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="6" style="text-align:center; padding: 20px; color: #666;">
                        No analyses yet. Start tracking above.
                    </td>
                </tr>`;
            return;
        }

        history.forEach(item => {
            const row = document.createElement("tr");
            
            // Format timestamp nicely
            const date = new Date(item.timestamp).toLocaleString();
            
            row.innerHTML = `
                <td><b>${item.domain}</b></td>
                <td style="font-family: monospace; color: var(--accent);">${item.ip_address}</td>
                <td>${item.country}</td>
                <td>${item.latitude.toFixed(2)}, ${item.longitude.toFixed(2)}</td>
                <td><span class="badge ${item.threat_level.toLowerCase()}">${item.threat_level}</span></td>
                <td style="font-size: 0.85rem; color: var(--text-muted);">${date}</td>
            `;
            historyBody.appendChild(row);
        });

    } catch (err) {
        console.error("Failed to load history:", err);
    }
}

/**
 * Smart UI: Typing effect for status updates
 */
function updateStatus(msg, type) {
    statusMsg.style.opacity = 0;
    setTimeout(() => {
        statusMsg.textContent = msg;
        statusMsg.className = "status-msg " + type;
        statusMsg.style.opacity = 1;
    }, 150);
}

/**
 * Enhanced Visuals: Cinematic Map Movement
 */
function animateToLocation(data) {
    // Clear old markers to keep map clean (optional)
    markersLayer.clearLayers();

    const color = COLORS[data.threat_level] || COLORS.UNKNOWN;
    
    // Create professional ring marker
    const marker = L.circleMarker([data.latitude, data.longitude], {
        radius: 12,
        fillColor: color,
        color: "#fff",
        weight: 3,
        fillOpacity: 0.9,
    });

    marker.bindPopup(`
        <div style="text-align:center; font-family:'Inter',sans-serif; color: #333;">
            <b style="font-size:1.1rem">${data.domain}</b><br>
            <span style="color:#555">${data.ip_address}</span><br>
            <span class="badge ${data.threat_level.toLowerCase()}" style="margin-top:5px; display:inline-block;">
                ${data.threat_level}
            </span>
        </div>
    `);

    marker.addTo(markersLayer);

    // High-speed Fly Animation
    map.flyTo([data.latitude, data.longitude], MAP_ZOOM_LEVEL, {
        animate: true,
        duration: 2.0 // Seconds
    });
    
    setTimeout(() => marker.openPopup(), 2100);
}

function renderData(data) {
    document.getElementById("resDomain").textContent  = data.domain;
    document.getElementById("resIP").textContent       = data.ip_address;
    document.getElementById("resCountry").textContent  = data.country;
    document.getElementById("resCoords").textContent   = `${data.latitude}, ${data.longitude}`;

    const badge = document.getElementById("resThreat");
    badge.textContent = data.threat_level;
    badge.className   = "badge " + data.threat_level.toLowerCase();

    resultCard.classList.add("visible");
}

init();

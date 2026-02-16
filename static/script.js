/**
 * script.js — GeoTrace Pro Logic
 */

// ── Configuration ──
const MAP_ZOOM_LEVEL = 8;
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
    SAFE:    "#2ecc71",
    TRACKER: "#f1c40f",
    UNKNOWN: "#e74c3c",
};

// ── DOM References ──
const domainInput  = document.getElementById("domainInput");
const analyzeBtn   = document.getElementById("analyzeBtn");
const statusMsg    = document.getElementById("statusMsg");
const resultCard   = document.getElementById("resultCard");
const historyBody  = document.getElementById("historyBody");

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
        loadHistory(); 

    } catch (err) {
        updateStatus("📡 Connection Timeout. Is the node online?", "error");
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze";
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
        <div style="text-align:center; font-family:'Inter',sans-serif;">
            <b style="font-size:1.1rem">${data.domain}</b><br>
            <span style="color:#888">${data.ip_address}</span><br>
            <span class="badge ${data.threat_level.toLowerCase()}">${data.threat_level}</span>
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

// ── Event Bindings ──
analyzeBtn.addEventListener("click", analyzeDomain);
domainInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyzeDomain();
});

// Load history on startup
async function init() {
    await loadHistory();
    // Logic: loadHistoryMarkers() can be added here if you want previous pins 
}

init();

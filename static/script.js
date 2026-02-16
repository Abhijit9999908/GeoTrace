/**
 * script.js — Frontend logic for GeoTrace
 *
 * Handles:
 *  - Sending domain to /analyze
 *  - Displaying results on the map and in the result card
 *  - Loading and rendering analysis history
 */

// ── Initialize the Leaflet map ──
// Center on (20, 0) with zoom level 2 to show the whole world
const map = L.map("map").setView([20, 0], 2);

// Add OpenStreetMap tile layer (free, no API key needed)
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
    maxZoom: 18,
}).addTo(map);

// Layer group to hold all markers (makes it easy to manage them)
const markersLayer = L.layerGroup().addTo(map);

// ── Color mapping for threat levels ──
const COLORS = {
    SAFE:    "#2ecc71",  // green
    TRACKER: "#f1c40f",  // yellow
    UNKNOWN: "#e74c3c",  // red
};

// ── DOM element references ──
const domainInput  = document.getElementById("domainInput");
const analyzeBtn   = document.getElementById("analyzeBtn");
const statusMsg    = document.getElementById("statusMsg");
const resultCard   = document.getElementById("resultCard");
const historyBody  = document.getElementById("historyBody");

// ── Analyze button click handler ──
analyzeBtn.addEventListener("click", analyzeDomain);

// Also trigger analysis when user presses Enter in the input
domainInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") analyzeDomain();
});

/**
 * Send the domain to the backend for analysis,
 * then update the UI with the result.
 */
async function analyzeDomain() {
    const domain = domainInput.value.trim();

    // Basic validation
    if (!domain) {
        showStatus("Please enter a domain name.", "error");
        return;
    }

    // Disable button while processing
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span class="spinner"></span> Analyzing...';
    showStatus("Resolving domain and fetching geolocation...", "");

    try {
        // Send POST request to the Flask backend
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain }),
        });

        const data = await response.json();

        // Check if the backend returned an error
        if (!response.ok) {
            showStatus(data.error || "Something went wrong.", "error");
            return;
        }

        // Success – update everything
        showStatus(Analysis complete for ${data.domain}, "success");
        displayResult(data);
        addMarker(data);
        loadHistory();  // Refresh the history table

    } catch (err) {
        showStatus("Network error. Is the server running?", "error");
        console.error(err);
    } finally {
        // Re-enable the button
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze";
    }
}

/**
 * Display a status message below the input.
 * @param {string} msg  – Message text
 * @param {string} type – "error", "success", or "" (neutral)
 */
function showStatus(msg, type) {
    statusMsg.textContent = msg;
    statusMsg.className = "status-msg " + type;
}

/**
 * Show the result card with analysis details.
 * @param {Object} data – The analysis result from the backend
 */
function displayResult(data) {
    document.getElementById("resDomain").textContent  = data.domain;
    document.getElementById("resIP").textContent       = data.ip_address;
    document.getElementById("resCountry").textContent  = data.country;
    document.getElementById("resCoords").textContent   = ${data.latitude}, ${data.longitude};

    // Set the threat badge
    const badge = document.getElementById("resThreat");
    badge.textContent = data.threat_level;
    badge.className   = "badge " + data.threat_level.toLowerCase();

    // Make the card visible
    resultCard.classList.add("visible");
}

/**
 * Add a color-coded marker to the map.
 * @param {Object} data – Must have latitude, longitude, domain, country, threat_level
 */
function addMarker(data) {
    const color = COLORS[data.threat_level] || COLORS.UNKNOWN;

    // Create a circle marker with the threat color
    const marker = L.circleMarker([data.latitude, data.longitude], {
        radius: 9,
        fillColor: color,
        color: "#fff",
        weight: 2,
        opacity: 1,
        fillOpacity: 0.85,
    });

    // Attach a popup with analysis details
    marker.bindPopup(`
        <strong>${data.domain}</strong><br>
        IP: ${data.ip_address}<br>
        Country: ${data.country}<br>
        Threat: <span style="color:${color};font-weight:700">${data.threat_level}</span>
    `);

    // Add to the markers layer and open popup
    marker.addTo(markersLayer);
    marker.openPopup();

    // Pan the map to the new marker
    map.setView([data.latitude, data.longitude], 5, { animate: true });
}

/**
 * Fetch the analysis history from the backend and render the table.
 */
async function loadHistory() {
    try {
        const response = await fetch("/history");
        const history  = await response.json();

        // Clear existing rows
        historyBody.innerHTML = "";

        if (history.length === 0) {
            historyBody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="6">No analyses yet. Enter a domain above to get started.</td>
                </tr>`;
            return;
        }

        // Build a row for each record
        history.forEach((item) => {
            const color = COLORS[item.threat_level] || COLORS.UNKNOWN;
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${item.domain}</td>
                <td>${item.ip_address}</td>
                <td>${item.country}</td>
                <td>${item.latitude}, ${item.longitude}</td>
                <td><span class="badge ${item.threat_level.toLowerCase()}">${item.threat_level}</span></td>
                <td>${item.timestamp}</td>
            `;

            // Clicking a history row re-centers the map on that location
            row.style.cursor = "pointer";
            row.addEventListener("click", () => {
                map.setView([item.latitude, item.longitude], 5, { animate: true });
            });

            historyBody.appendChild(row);
        });

    } catch (err) {
        console.error("Failed to load history:", err);
    }
}

/**
 * Load existing markers from history onto the map.
 */
async function loadHistoryMarkers() {
    try {
        const response = await fetch("/history");
        const history  = await response.json();

        history.forEach((item) => {
            const color = COLORS[item.threat_level] || COLORS.UNKNOWN;
            const marker = L.circleMarker([item.latitude, item.longitude], {
                radius: 7,
                fillColor: color,
                color: "#fff",
                weight: 1.5,
                opacity: 0.8,
                fillOpacity: 0.7,
            });

            marker.bindPopup(`
                <strong>${item.domain}</strong><br>
                IP: ${item.ip_address}<br>
                Country: ${item.country}<br>
                Threat: <span style="color:${color};font-weight:700">${item.threat_level}</span>
            `);

            marker.addTo(markersLayer);
        });

    } catch (err) {
        console.error("Failed to load history markers:", err);
    }
}

// ── On page load: fetch history and display existing markers ──
loadHistory();
loadHistoryMarkers();

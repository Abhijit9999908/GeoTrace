// script.js

// Domain Analysis
function analyzeDomain(domain) {
    const urlPattern = new RegExp('^(https?://)?(www\.)?([a-z0-9-]+)(\.[a-z]{2,})');
    const match = domain.match(urlPattern);
    if (match) {
        return {
            protocol: match[1] ? match[1] : 'http://',
            domainName: match[3],
            tld: match[4]
        };
    }
    return null;
}

// Map Initialization
function initMap() {
    const map = L.map('map').setView([51.505, -0.09], 13);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
    }).addTo(map);
    return map;
}

// History Management
const historyStack = [];

function addToHistory(action) {
    historyStack.push(action);
    console.log('Current History: ', historyStack);
}

function getHistory() {
    return historyStack;
}

// Example usage:
const domainInfo = analyzeDomain('https://www.example.com');
console.log(domainInfo);

const map = initMap();
addToHistory('Initialized map at example.com');
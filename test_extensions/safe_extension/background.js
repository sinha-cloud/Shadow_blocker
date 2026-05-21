// Safe background script
chrome.alarms.onAlarm.addListener((alarm) => {
    console.log(`Alarm triggered: ${alarm.name}`);
    if (alarm.name === 'sync-notes') {
        syncNotesWithStorage();
    }
});

function syncNotesWithStorage() {
    chrome.storage.local.get(['notes'], (result) => {
        const notes = result.notes || [];
        console.log(`Syncing ${notes.length} notes...`);
        // Simulating normal operation
    });
}

// Safe content script
console.log("Sleek Note Taker loaded!");

// Simulates adding a safe notes container to the page
function injectNotesButton() {
    const btn = document.createElement("button");
    btn.innerText = "Take Note";
    btn.style.position = "fixed";
    btn.style.bottom = "20px";
    btn.style.right = "20px";
    btn.style.zIndex = "99999";
    btn.addEventListener("click", () => {
        const note = prompt("Enter a note:");
        if (note) {
            chrome.storage.local.get(['notes'], (result) => {
                const notes = result.notes || [];
                notes.push(note);
                chrome.storage.local.set({ notes }, () => {
                    console.log("Note saved!");
                });
            });
        }
    });
    document.body.appendChild(btn);
}

// Injects only on interactive state
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", injectNotesButton);
} else {
    injectNotesButton();
}

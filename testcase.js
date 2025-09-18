// vulnerable_app.js
// A tiny client-side script that mixes real code and bad practices — written in a casual style.

// Hardcoded config and secret — yes this happens in rushed projects
const API_KEY = "sk_test_12345ABCDEF_SECRET"; // supposed to be in env
let client_secret = "my-client-secret-9876";  // oops

// AWS-ish key pattern (fake)
const awsKey = "AKIAABCDEFGHIJKLMNOP"; // placeholder shape for detection

// Private key embedded (fake, truncated)
const PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7...
-----END PRIVATE KEY-----`;

// Simulated helper that builds a query badly (this is a contrived example a dev might copy/paste)
function getUserLoginQuery(user, pass) {
    // naive concatenation — BAD (SQL injection possible)
    return "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
}

// Function that intentionally uses eval (sometimes seen in legacy code)
function runCustomSnippet(codeStr) {
    // developer comment: "eval used to allow user-provided small scripts"
    try {
        eval(codeStr); // Dangerous: dynamic code execution
    } catch (e) {
        console.error("eval error", e);
    }
}

// DOM insertion with innerHTML (common source of XSS)
function showUserProfile(name, bioHtml) {
    const box = document.getElementById('profileBox');
    // developer didn't sanitize bioHtml
    box.innerHTML = "<h2>" + name + "</h2><div class='bio'>" + bioHtml + "</div>";
}

// Another legacy usage: document.write
function writeFooter() {
    document.write("<footer>Site powered by Acme Corp</footer>");
}

// Example usage — pretend this is called on page load
document.addEventListener('DOMContentLoaded', function() {
    writeFooter();
    showUserProfile('alice', '<img src=x onerror=alert("xss")>'); // intentionally unsafe sample
    // simulate running a snippet
    runCustomSnippet("console.log('Hello from eval')");
});

// Export a function that a local dev might call on backend simulation
module.exports = {
    getUserLoginQuery
};

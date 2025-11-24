const fs = require("fs");
const readline = require("readline");
const { google } = require("googleapis");

// Load your OAuth credentials from a local file or environment variables
let client_id, client_secret, redirect_uris;
try {
  // Prefer a local credentials file (keep it out of git)
  const raw = fs.readFileSync('credentials.json', 'utf8');
  const parsed = JSON.parse(raw);
  ({ client_id, client_secret, redirect_uris } = parsed.installed || parsed);
} catch (err) {
  // Fallback to environment variables
  client_id = process.env.GOOGLE_CLIENT_ID;
  client_secret = process.env.GOOGLE_CLIENT_SECRET;
  redirect_uris = [process.env.GOOGLE_REDIRECT_URI || 'urn:ietf:wg:oauth:2.0:oob'];
}

if (!client_id || !client_secret) {
  console.error('Missing Google OAuth credentials. Provide a credentials.json or set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.');
  process.exit(1);
}
const oAuth2Client = new google.auth.OAuth2(
  client_id,
  client_secret,
  redirect_uris[0]
);

// Generate authorization URL
const authUrl = oAuth2Client.generateAuthUrl({
  access_type: "offline",
  scope: ["https://mail.google.com/"],
});

console.log("Authorize this app by visiting this URL:", authUrl);

// Read the authorization code
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question("Enter the code from that page here: ", (code) => {
  oAuth2Client.getToken(code, (err, token) => {
    if (err) return console.error("Error retrieving access token", err);
    console.log("\nYOUR REFRESH TOKEN:\n", token.refresh_token);
    rl.close();
  });
});

const parserFactory = require('../parsers/parserFactory');

const sample = `Time
Level
Category
Log
1:58:02 AM
info
Startup
GET [Sun - Status 200
1:58:02 AM
unknown
Request Processing
169.4.225.212 - - [05/Sep/2026:20:28:02 +0000] "GET 194.24.0.131 - - [01/Jul/2026:19:32:21 +0000] "GET /index.html HTTP/1.1" 200 2737 "-" "curl/8.5.0" HTTP/1.1" 200 512 "-" "curl/8.5.0"
1:58:02 AM
error
Security
172.20.185.198 - - [05/Sep/2026:20:28:02 +0000] "GET 157.215.79.224 - - [01/Jul/2026:00:11:21 +0000] "GET /login HTTP/1.1" 200 2649 "https://twitter.com/" "Mozilla/5.0 (X11; Linux x86_64)" HTTP/1.1" 200 512 "-" "curl/8.5.0"
1:58:02 AM
unknown
Request Processing
67.68.216.247 - - [05/Sep/2026:20:28:02 +0000] "GET 193.189.36.18 - - [01/Jul/2026:19:17:54 +0000] "GET /index.html HTTP/1.1" 200 490 "https://www.bing.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X)" HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
1:58:02 AM
info
Worker Initialization
GET [Sun - Status 200
1:58:02 AM
unknown
Request Processing
158.43.253.65 - - [05/Sep/2026:20:28:02 +0000] "GET 68.236.185.161 - - [01/Jul/2026:06:27:24 +0000] "POST /index.html HTTP/1.1" 200 660 "https://facebook.com/" "Bingbot/2.0" HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
1:58:02 AM
info
Startup
GET [Sun - Status 200
1:58:02 AM
unknown
Security
193.246.211.105 - - [05/Sep/2026:20:28:02 +0000] "GET 28.51.18.144 - - [01/Jul/2026:05:02:03 +0000] "GET /index.html HTTP/1.1" 200 153 "https://facebook.com/" "python-requests/2.32.0" HTTP/1.1" 200 512 "-" "acunetix"
1:58:02 AM
unknown
Request Processing
210.49.127.63 - - [05/Sep/2026:20:28:02 +0000] "GET 62.182.73.112 - - [01/Jul/2026:09:13:52 +0000] "GET /index.html HTTP/1.1" 200 2485 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/137.0" HTTP/1.1" 200 512 "-" "curl/8.5.0"
1:58:02 AM
unknown
Security
104.67.157.165 - - [05/Sep/2026:20:28:02 +0000] "GET 130.155.102.189 - - [01/Jul/2026:15:26:55 +0000] "DELETE /index.html HTTP/1.1" 200 1001 "https://www.bing.com/" "Googlebot/2.1" HTTP/1.1" 200 512 "-" "acunetix"`;

console.log('Sample length:', sample.split(/\r?\n/).length);

try {
  const parser = parserFactory.getParser(sample);
  const result = parser.parseFile(sample);
  console.log('Detected parser:', parser.formatName);
  console.log('Parsed entries:', JSON.stringify(result, null, 2));
} catch (err) {
  console.error('Parser error:', err.message);
}

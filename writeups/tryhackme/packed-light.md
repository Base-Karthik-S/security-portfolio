# Hacker Holidays – Packed Light (Forensics) Write-up

## Objective

Analyze a network capture (`traffic.pcapng`) to identify a covert communication channel, recover the exfiltrated data, decode it, and obtain the flag.

## Initial Analysis

The challenge description suggested:

* Regular HTTP requests to port **8080**
* Suspicious HTTP request headers
* Possible encrypted or encoded data

Using Wireshark, I filtered the traffic and followed the relevant TCP stream.

## Malware Analysis

The HTTP response contained a Python script (`updates.py`) acting as a keylogger.

Key observations:

* Captured every keystroke using `pynput`.
* XOR-encrypted each character with the key:

  ```
  H0t3lSt@ff0NlyK3epS3cr3t!
  ```
* Base64-encoded the encrypted byte.
* Exfiltrated each keystroke inside the HTTP **Cookie** header:

  ```
  Cookie: hotel_sess_state=<Base64>
  ```

## Recovering the Data

To identify the covert channel:

1. Filtered HTTP packets containing the Cookie header.
2. Added the Cookie field as a custom Wireshark column.
3. Collected each `hotel_sess_state` value.
4. Used a short Python script to:

   * Base64 decode each value.
   * XOR it using the first byte of the key (each transmission contained a single encrypted character).
5. Reassembled the recovered plaintext to reveal the complete exfiltrated data and obtain the flag.

## Skills Demonstrated

* Network traffic analysis with Wireshark
* HTTP protocol inspection
* Malware and Python code analysis
* Identifying covert data exfiltration channels
* Base64 decoding
* XOR decryption
* Python scripting for forensic analysis

## Key Takeaway

Rather than attempting to decode traffic blindly, analysing the malware first revealed exactly how the data was being hidden and encrypted, making recovery straightforward and demonstrating the importance of combining malware analysis with network forensics.

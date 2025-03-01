# XSS Vulnerability Scanner

![Banner](https://github.com/mahaveer-choudhary/xss-scanner/blob/main/images/img1.png)

A Python-based tool to detect Cross-Site Scripting (XSS) Vulnerabilities in web applications. This tool uses Selenium to automate the process of injecting payloads into URLs and checking for potential XSS vulnerabilities.

---

## Features

- **Automated Scanning** : Automatically scans URLs for XSS vulnerabilities using a list of payloads.
- **Multi-threading** : Utilizes multi-threading to speed up the scanning process.
- **Headless Mode** : Runs in headless mode for faster execution.
- **HTML Report** : Generates a detailed HTML report of the scan result.
- **User-friendly Interface** : Provides a command-line interface with color-coded output for better readability.

---

## Installation

### Prerequisites

Before running the tool, ensure you have the following installed : 

1. **Python 3.x** : Download and install python from [python.org](https://www.python.org).
2. **Chrome or Chromium Browser** : Make sure you have Chrome or Chromium installed.
3. **ChromeDriver** : Download the version of ChromeDriver that matches you chrome broswer version from [here](https://sites.google.com/chromium.org/driver/).



### Steps to Install 

1. **Clone the repository** : 
    Open you terminal and run the following command to clone the repository : 
    ```bash
    git clone https://github.com/mahaveer-choudhary/xss-scanner.git
    cd xss-scanner
    ```

2. **Install Python dependencies** : 
    Install the required Python packages using ```pip```: 
    ```bash
    pip install -r requirements.txt
    ```

---

### Setup Payload Files 

The tool requires a file containing XSS payloads to test against the target URLs. Follow these steps to set up the payload file : 

1. **Create a payload file** : 
    Create a text file named ```payloads.txt``` (or any name you prefer) in the project directory.

2. **Add XSS payloads**: 
    Add you XSS payloads to the file, with each payload on a new line. Foe example : 
    ```bash
    <script>alert(1)</script>
    <img scr=x onerror=alert(1)>
    "><svg/onload=alert(1)>
    ```

3. **Save the file**: 
    Save the file in the project directory. You will provide the path to this file when running the tool. 

---

## Usage 

### Running the Tool 

1. **Start the scanner**: 
    Run the following command in you terminal : 
    ```bash
    python xss-scanner.py
    ```

2. **Provide inputs**:
    - **URLs**: You will be prompted to enter either a single URL or a file containing multiple URLs.

    - **Payloads File** : Provide the path to the ```payloads.txt``` file (or the file you created).

    - **Timeout**: Enter the timeout duration for each request (default is 0.5 seconds).

3. **Scanning processs**: 
    - The tool will start scanning the provided URLs with the payloads.
    - It will display the results in the terminal, indicating whether each URL is vulnerable or not. 

4. **Generate HTML report**: 
    - AFter the scan completes, you will be prompted to generate an HTML report.
    - Enter `y` to generate the report and provide a filename (or press Enter to use the default `xssreport.html`).

---

## Example

Here's an example of how to use the tool : 

![videosample](https://via.placeholder.com/800x200.png?text=XSS+Vulnerability+Scanner)

---

## HTML Report 
The tool geneartes a detailed HTML report with the following information : 
- **Total Vulnerabilities found**
- **Total URLs scanned**
- **Time Taken**
- **Vulnerable URLs Grouped by Doamin**

here's a sample screenshot of the HTML report : 

![html_report](https://via.placeholder.com/800x200.png?text=XSS+Vulnerability+Scanner)

---

## Disclaimer 
This tool is intended for educational and ethical testing purposes only. Do not use it for any malicious activities. The authors are not responsible for any misuse of this tool. 


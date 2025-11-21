# Email Header Forensic Analysis

A Python-based forensic toolkit to analyze email headers, trace routing paths, validate SPF/DKIM/DMARC, detect spoofing, and automatically generate a clean PDF investigation report.

---

## 📌 Features

- ✔ Extracts and parses all major email metadata  
- ✔ Reconstructs hop-by-hop routing timeline  
- ✔ Performs PTR & WHOIS lookups on all hops  
- ✔ Validates SPF, DKIM, and DMARC authentication  
- ✔ Detects multiple spoofing indicators  
- ✔ Generates a multi-page PDF forensic report  
- ✔ Works on both Windows and Linux  
- ✔ Simple and intuitive CLI usage  

---

## 📁 Project Structure
```
Email_Header_Analysis/
│
├── header_analysis.py # Core forensic engine
├── report_generator.py # PDF report generator
├── header.txt # Sample real email header
├── spoofedheader.txt # Sample spoofed email header
└── README.md # Project documentation
```

---

## 🚀 How It Works

### **1. Input**
Provide any raw email header as a `.txt` file.

---

### **2. Analysis (header_analysis.py)**

The script performs:

#### **Metadata Extraction**
- From  
- To  
- Subject  
- Date  
- Message-ID  

#### **Routing Timeline Reconstruction**
- Parses all `Received:` headers  
- Extracts IPs, hostnames/HELO, timestamps  
- Orders hops from origin → destination  

#### **Network Intelligence**
- PTR (reverse DNS) lookup  
- WHOIS lookup (organization, ASN, country)  

#### **Authentication Validation**
- SPF  
- DKIM  
- DMARC  

#### **Spoof Detection**
Flags indicators such as:
- Missing or malformed metadata  
- Private IP as the first hop  
- Unknown HELO or inconsistent handshake  
- Missing SPF/DKIM/DMARC  
- Broken timestamp chains  

---

### **3. PDF Report Generation (report_generator.py)**

Automatically creates a clean PDF containing:

- Title + case metadata  
- Full analysis output  
- Routing timeline  
- Authentication results  
- Spoofing indicators  
- Paginated, professional formatting  

Perfect for:
- SOC reports  
- Academic submissions  
- Digital forensics documentation  

---

## 📦 Installation

### **1. Clone the Repository**
```bash
git clone https://github.com/saiavinash05/Email_Header_Analysis
cd Email_Header_Analysis
```

### **2. Install Dependencies**
```bash
pip install reportlab dnspython python-whois
```

## ▶ Usage

### Run Header Analysis Only
python header_analysis.py header.txt

### Generate PDF Report
python report_generator.py header.txt output.pdf

### Example
python report_generator.py spoofedheader.txt spoofed_report.pdf

---

## 📊 Output Examples

### Spoofed Email Detection
- Missing From / Subject / Date  
- First hop uses private IP  
- Unknown HELO  
- No SPF/DKIM/DMARC records  
➡ **Marked as spoofed**

### Legitimate Email Analysis
- Valid DKIM signature  
- SPF = pass  
- Valid DMARC policy  
- Consistent hop timeline  
➡ **Marked as authentic**

---

## 🛠 Tech Stack

- Python 3  
- `email` – Header parsing  
- `dnspython` – DNS lookups  
- `whois` – Domain WHOIS lookup  
- `socket` – Reverse DNS  
- `reportlab` – PDF generation  
- `subprocess` – Script chaining  

---

## 📚 Use Cases

- Cybersecurity training  
- SOC investigations  
- Mail server audits  
- Digital forensics coursework  
- Academic research  
- Real-world phishing analysis  
- Incident response workflows  

---

## 📌 Conclusion

This project provides a reliable, automated pipeline for identifying spoofed emails, analyzing their routing path, and validating authentication mechanisms.

With integrated PDF report generation, it is suited for:

- Cybersecurity teams  
- SOC & DFIR operations  
- Academic labs  
- Professional investigation reports  

A complete toolkit for modern email header forensics.

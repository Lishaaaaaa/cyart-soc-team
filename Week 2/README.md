
1. Alert detection
The security alerts were produced by Wazuh SIEM for monitored endpoints.
These include phishing alerts, SSH brute-force attacks, and exploitation attempts within a controlled lab environment.

2. Alert Category and Prioritization
The alerts identified were categorized based on their type and linked with the various MITRE ATT&CK techniques.
The assignment of priorities utilized severity levels, the criticality of assets, and CVSS scores.


3. Alert Visualization
A dashboard for Wazuh was developed to display data on alert severity through pie charts, facilitating the monitoring of critical and high alerts.

4. Alert Triage and Validation The alerts were evaluated to identify true positive results and false positive results. Threat intelligence platforms like VirusTotal, as well as AlienVault OTX, were employed to confirm IP addresses and file hashes.

5. Containment and Response  
   Affected systems were isolated, and malicious IP addresses were blocked using CrowdSec to prevent further exploitation.

6. Evidence Preservation  
   Volatile and non-volatile evidence was collected using Velociraptor, including network connection data and memory dumps.  
   Collected evidence was hashed using SHA-256 to ensure integrity.

7. Recovery  
   Systems were monitored and restored to normal operation after confirming that no malicious activity remained.

8. Documentation and Reporting  
   All activities, findings, and responses were documented using a SANS-style incident response template and converted to PDF for submission.

10. Post-Incident Review  
    Lessons learned were identified to improve detection, response procedures, and overall SOC readiness.

from flask import Flask, request, render_template, send_file, jsonify
import nmap
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

app = Flask(__name__)

# Initialize the nmap PortScanner
nm = nmap.PortScanner()

# Scan function
def run_nmap_scan(target, scan_type):
    if scan_type == 'Quick':
        scan_args = '-F'
    elif scan_type == 'Full':
        scan_args = '-sS -sV -T4'
    elif scan_type == 'Vulnerability':
        scan_args = '--script ssl-heartbleed,ssl-poodle,http-vuln-cve2017-5638 --max-retries 1 --host-timeout 30m -T4'
    else:
        return {'error': 'Invalid scan type'}
    
    try:
        nm.scan(hosts=target, arguments=scan_args)
        scan_results = {}
        for host in nm.all_hosts():
            scan_results[host] = {
                'hostnames': nm[host].hostnames(),
                'state': nm[host].state(),
                'protocols': {},
                'vulnerabilities': [] if scan_type == 'Vulnerability' else None  # Add vulnerabilities field for vuln scan
            }
            for protocol in nm[host].all_protocols():
                scan_results[host]['protocols'][protocol] = []
                for port, info in nm[host][protocol].items():
                    service_info = {
                        'port': port,
                        'service': info['name'],
                        'status': info['state']
                    }
                    if scan_type == 'Vulnerability':
                        # Check for vulnerabilities
                        if 'Vulnerability' in info:
                            scan_results[host]['vulnerabilities'].append(info['Vulnerability'])
                    scan_results[host]['protocols'][protocol].append(service_info)
        return scan_results
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'Quick')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    scan_results = run_nmap_scan(target, scan_type)
    return jsonify(scan_results)

@app.route('/generate_pdf/<target>/<scan_type>', methods=['GET'])
def generate_pdf(target, scan_type):
    scan_results = run_nmap_scan(target, scan_type)

    if 'error' in scan_results:
        return jsonify(scan_results), 400

    # Create a PDF in memory
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 12)
    
    pdf.drawString(100, 750, f"Scan Report for Target: {target}")
    pdf.drawString(100, 730, f"Scan Type: {scan_type}")
    pdf.drawString(100, 710, "Scan Results:")

    y_position = 690
    for host, details in scan_results.items():
        pdf.drawString(100, y_position, f"Host: {host} (State: {details['state']})")
        y_position -= 20
        for protocol, ports in details['protocols'].items():
            pdf.drawString(100, y_position, f"Protocol: {protocol}")
            y_position -= 20
            for service_info in ports:
                pdf.drawString(120, y_position, f"Port {service_info['port']}: {service_info['service']} ({service_info['status']})")
                y_position -= 20
            if scan_type == 'Vulnerability' and details['vulnerabilities']:
                pdf.drawString(100, y_position, "Vulnerabilities:")
                for Vulnerability in details['vulnerabilities']:
                    y_position -= 20
                    pdf.drawString(120, y_position, f"- {Vulnerability}")
        y_position -= 10  # Add extra space between hosts
    
    pdf.save()

    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"VulnScan_Automator_report_{target.replace('.', '_')}.pdf", mimetype="application/pdf")

@app.route('/report/<target>', methods=['GET'])
def view_report(target):
    scan_type = request.args.get('scan_type', 'Quick')
    scan_results = run_nmap_scan(target, scan_type)
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if 'error' in scan_results:
        return render_template('report_view.html', error=scan_results['error'])
    
    # Add PDF download link below the view report
    pdf_download_url = f"/generate_pdf/{target}/{scan_type}"
    return render_template('report_view.html', target=target, scan_results=scan_results, scan_type=scan_type, date=date, pdf_download_url=pdf_download_url)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
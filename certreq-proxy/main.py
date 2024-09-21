from flask import Flask, request, jsonify, Response
from functools import wraps
import base64
import subprocess
import tempfile
import os

app = Flask(__name__)

USERNAME = 'login'
PASSWORD = 'password'

def check_auth(username, password):
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    """Decorator to enforce authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        # if not auth:
        #     return authenticate()
        # elif not check_auth(auth.username, auth.password):
        #     return authenticate()
        return f(*args, **kwargs)
    return decorated

def execute_certreq_command(command):
    """Executes a certreq command and returns the return code and output."""
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        output = result.stdout + result.stderr
        return result.returncode, output
    except Exception as e:
        raise Exception(f'Failed to execute certreq: {str(e)}')

def parse_certreq_output(output):
    """
    Parses the output from certreq and returns the status, request ID, and error text.
    Excludes RequestId lines from error text.
    """
    status = 'Unknown'
    request_id = ''
    status_text_lines = []

    for line in output.splitlines():
        stripped_line = line.strip()
        if 'RequestId:' in stripped_line:
            if not request_id:
                request_id = stripped_line.split('RequestId:')[1].strip().strip('"')
        elif 'Certificate retrieved' in stripped_line or 'Certificate Issued' in stripped_line or 'Valid' in stripped_line:
            status_text_lines.append(stripped_line)
            status = 'Ready'
        elif 'Certificate request is pending' in stripped_line or 'The request was submitted to the certification authority' in stripped_line:
            status_text_lines.append(stripped_line)
            status = 'Pending'
        elif 'Request denied' in stripped_line or 'Denied by Policy Module' in stripped_line:
            status_text_lines.append(stripped_line)
            status = 'Rejected'
        elif 'Error' in stripped_line or '0x' in stripped_line:
            status = 'Errored'
            status_text_lines.append(stripped_line)
        else:
            status_text_lines.append(stripped_line)

    error_text = '\n'.join(status_text_lines).strip()
    return status, request_id, error_text

# Replace with your actual CA IP or name
CA_IP = 'CA_IP'

@app.route('/requestCertificate', methods=['POST'])
@requires_auth
def request_certificate():
    data = request.get_json()
    print(data)
    if not data or 'csr' not in data or 'template_name' not in data:
        return jsonify({'error': 'Invalid input'}), 400

    csr_b64 = data['csr']
    template_name = data['template_name']

    try:
        csr_bytes = base64.b64decode(csr_b64)
    except Exception:
        return jsonify({'error': 'Invalid base64 CSR'}), 400

    with tempfile.NamedTemporaryFile(delete=False, suffix='.csr') as csr_file:
        csr_file_name = csr_file.name
        csr_file.write(csr_bytes)
        csr_file.close()

    command = [
        'certreq', '-submit', "-q", '-attrib', f'CertificateTemplate:{template_name}',
        '-config', CA_IP, csr_file_name
    ]

    try:
        returncode, output = execute_certreq_command(command)
    except Exception as e:
        os.unlink(csr_file_name)
        return jsonify({'error': str(e)}), 500
    finally:
        os.unlink(csr_file_name)

    status, request_id, error_text = parse_certreq_output(output)

    response = {
        'status': status,
        'status_description': error_text,
        'request_id': request_id,
    }
    print(response)

    return jsonify(response)

@app.route ('/getCA', methods=['GET'])
@requires_auth
def get_ca():
    with tempfile.NamedTemporaryFile(delete=True, suffix='.ca') as cert_file:
        cert_file_name = cert_file.name

    command = [
        'certutil', '-ca.cert', '-config', CA_IP, cert_file_name
    ]

    try:
        returncode, output = execute_certreq_command(command)
    except Exception as e:
        os.unlink(cert_file_name)
        return jsonify({'error': str(e)}), 500

    if 'Valid' in output:
        status = 'Ready'
    else:
        status = 'Errored'
    
    error_text = output

    if status == 'Ready':
        certificate_text = output.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0]
        certificate_text = '-----BEGIN CERTIFICATE-----\n' + certificate_text + '\n-----END CERTIFICATE-----'
        certificate = base64.b64encode(certificate_text.encode('utf-8')).decode('utf-8')
    else:
        certificate = ''

    os.unlink(cert_file_name)

    response = {
        'status': status,
        'certificate': certificate,
        'status_description': error_text,
    }

    return jsonify(response)

@app.route('/getCertificate', methods=['POST'])
@requires_auth
def get_certificate():
    data = request.get_json()
    print(data)
    if not data or 'request_id' not in data:
        return jsonify({'error': 'Invalid input'}), 400

    request_id = data['request_id']

    with tempfile.NamedTemporaryFile(delete=False, suffix='.cer') as cert_file:
        cert_file_name = cert_file.name

    command = [
        'certreq', '-retrieve', '-q', '-f', '-config', CA_IP, str(request_id), cert_file_name
    ]

    try:
        returncode, output = execute_certreq_command(command)
    except Exception as e:
        os.unlink(cert_file_name)
        return jsonify({'error': str(e)}), 500

    status, _, error_text = parse_certreq_output(output)

    if status == 'Ready':
        with open(cert_file_name, 'rb') as f:
            cert_data = f.read()
        certificate = base64.b64encode(cert_data).decode('utf-8')
    else:
        certificate = ''

    os.unlink(cert_file_name)

    response = {
        'status': status,
        'certificate': certificate,
        'status_description': error_text,
        'request_id': request_id,
    }

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)

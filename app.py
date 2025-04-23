from flask import Flask, render_template, request, jsonify
import random

app = Flask(__name__)

DEFAULT_RULE = {
    "action": "alert",
    "protocol": "tcp",
    "source_ip": "any",
    "source_port": "any",
    "direction": "->",
    "dest_ip": "any",
    "dest_port": "any",
    "sameip": False,
    "options": {
        "msg": "Example rule",
        "sid": 1000001,
        "rev": 1,
        "classtype": "not-suspicious",
        "priority": 3,
        "content": "",
        "nocase": False,
        "depth": "",
        "offset": "",
        "distance": "",
        "within": "",
        "pcre": "",
        "flow": "",
        "flowbits": "",
        "uricontent": "",
        "http_method": "",
        "http_uri": "",
        "http_header": "",
        "http_cookie": "",
        "threshold": "",
        "metadata": "",
        "reference": "",
        "tag": ""
    }
}

CLASS_TYPES = [
    "not-suspicious", "unknown", "bad-unknown", "attempted-recon",
    "successful-recon-limited", "successful-recon-largescale",
    "attempted-dos", "successful-dos", "attempted-user", "unsuccessful-user",
    "successful-user", "attempted-admin", "successful-admin",
    "rpc-portmap-decode", "shellcode-detect", "string-detect",
    "suspicious-filename-detect", "suspicious-login", "system-call-detect",
    "tcp-connection", "trojan-activity", "unusual-client-port-connection",
    "network-scan", "denial-of-service", "non-standard-protocol",
    "protocol-command-decode", "web-application-activity",
    "web-application-attack", "misc-activity", "misc-attack",
    "icmp-event", "inappropriate-content", "policy-violation",
    "default-login-attempt", "sdf", "file-format", "malware-cnc",
    "client-side-exploit", "networks-scan", "admin-login-attempt"
]


@app.route('/')
def index():
    return render_template('index.html', classtypes=CLASS_TYPES)


@app.route('/api/classtypes', methods=['GET'])
def get_classtypes():
    return jsonify(CLASS_TYPES)


@app.route('/api/rule', methods=['GET', 'POST'])
def handle_rule():
    if request.method == 'GET':
        return jsonify(DEFAULT_RULE)
    elif request.method == 'POST':
        data = request.get_json()
        rule_text = generate_rule(data)
        return jsonify({"rule": rule_text})


@app.route('/api/validate', methods=['POST'])
def validate_rule():
    data = request.get_json()
    rule_text = data.get('rule', '')
    is_valid = bool(rule_text)  # Simple validation
    return jsonify({"valid": is_valid, "message": "Validation passed" if is_valid else "Empty rule"})


@app.route('/api/generate_sid', methods=['GET'])
def generate_sid():
    return jsonify({"sid": random.randint(1000000, 1999999)})


def generate_rule(rule_data):
    header = f"{rule_data['action']} {rule_data['protocol']} {rule_data['source_ip']} {rule_data['source_port']} {rule_data['direction']} {rule_data['dest_ip']} {rule_data['dest_port']}"

    options = []
    opts = rule_data['options']

    # Basic options
    if opts['msg']:
        options.append(f'msg:"{opts["msg"]}"')
    if opts['sid']:
        options.append(f'sid:{opts["sid"]}')
    if opts['rev']:
        options.append(f'rev:{opts["rev"]}')
    if opts['classtype']:
        options.append(f'classtype:{opts["classtype"]}')
    if opts['priority']:
        options.append(f'priority:{opts["priority"]}')

    # Content options
    if opts['content']:
        content = f'content:"{opts["content"]}"'
        if opts['nocase']:
            content += '; nocase'
        if opts['depth']:
            content += f'; depth:{opts["depth"]}'
        if opts['offset']:
            content += f'; offset:{opts["offset"]}'
        if opts['distance']:
            content += f'; distance:{opts["distance"]}'
        if opts['within']:
            content += f'; within:{opts["within"]}'
        options.append(content)

    # Other matching options
    if opts['pcre']:
        options.append(f'pcre:"{opts["pcre"]}"')
    if opts['uricontent']:
        options.append(f'uricontent:"{opts["uricontent"]}"')

    # HTTP options
    if opts['http_method']:
        options.append(f'http_method; content:"{opts["http_method"]}"')
    if opts['http_uri']:
        options.append(f'http_uri; content:"{opts["http_uri"]}"')
    if opts['http_header']:
        options.append(f'http_header; content:"{opts["http_header"]}"')
    if opts['http_cookie']:
        options.append(f'http_cookie; content:"{opts["http_cookie"]}"')

    # Flow options
    if opts['flow']:
        options.append(f'flow:{opts["flow"]}')
    if opts['flowbits']:
        options.append(f'flowbits:{opts["flowbits"]}')

    # Thresholding and tagging
    if opts['threshold']:
        options.append(f'threshold:{opts["threshold"]}')
    if opts['tag']:
        options.append(f'tag:{opts["tag"]}')

    # Metadata and references
    if opts['metadata']:
        options.append(f'metadata:{opts["metadata"]}')
    if opts['reference']:
        options.append(f'reference:{opts["reference"]}')

    if rule_data.get('sameip'):
        options.append('sameip')

    # Join options with semicolons and ensure the string ends with a semicolon
    options_str = '; '.join(options)
    if options_str:  # Only add semicolon if there are options
        options_str += ';'

    return f"{header} ({options_str})"


if __name__ == '__main__':
    app.run(debug=True)
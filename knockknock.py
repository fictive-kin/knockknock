from flask import Flask, Response
from flask import jsonify, request, session, redirect, url_for, escape, render_template
import boto
from boto.ec2 import connect_to_region
from boto.exception import NoAuthHandlerFound
import requests

app = Flask(__name__)

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login', _scheme=get_scheme(request), _external=True))

    # is logged in

    ip = get_ip(request)

    # fetch groups with a knockknock tag
    ec2_groups, max_ec2_groups = get_groups(ip)

    return render_template(
        'home.html',
        username=session['username'],
        ip=ip,
        ec2_groups=ec2_groups,
        max_ec2_groups=max_ec2_groups
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if validate_iam_user(request.form['username'], request.form['password'], app.config['account_id']):
            session['username'] = request.form['username']
            return redirect(url_for('index', _scheme=get_scheme(request), _external=True))
    return render_template('login.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('login', _scheme=get_scheme(request), _external=True))

@app.route('/change', methods=['POST'])
def change():
    group = None
    ip = get_ip(request)
    for g in get_groups(ip)[0]:
        if g['id'] == request.form['group_id']:
            group = g
            break

    if not group:
        return "Invalid group", 400

    port = int(request.form['port'])
    if port not in group['all_ports']:
        return "Invalid port: %s %s" % (request.form['port'], group['all_ports']), 400

    if 'grant' in request.form and request.form['grant']:
        app.logger.debug("auth: %s", group['boto_group'].authorize(
            ip_protocol='tcp',
            from_port=port,
            to_port=port,
            cidr_ip="%s/32" % ip
        ))
    else:
        app.logger.debug("revoke: %s", group['boto_group'].revoke(
            ip_protocol='tcp',
            from_port=port,
            to_port=port,
            cidr_ip="%s/32" % ip
        ))

    return redirect(url_for('index', _scheme=get_scheme(request), _external=True))

def ensure_secret(filename, app):
    try:
        secret = open(filename, 'r').read().strip()
        app.logger.debug('Found .secret file')
        if "" == secret:
            app.logger.debug('...but .secret file is empty')
            raise IOError("Invalid")
    except IOError:
        import os, binascii
        secret = binascii.b2a_hex(os.urandom(30))
        app.logger.debug('Generating new secret')
        open(filename, 'w').write(secret)

    return secret

def get_ip(request):
    # allow upstream proxy (nginx) to set X-Real-IP
    return request.headers.get('X-Real-Ip', request.remote_addr)

def get_scheme(request):
    ssl = request.headers.get('X-Forwarded-Ssl', None)
    if ssl is not None:
        if ssl == 'on':
            return 'https'
        else:
            return 'http'
    else:
        if request.is_secure:
            return 'https'
        else:
            return 'http'



def get_groups(ip):
    max_ec2_groups = 0
    ec2_groups = []
    for group in app.config['ec2_conn'].get_all_security_groups(filters={"tag-key":"knockknock"}):
        all_ports = map(int, group.tags['knockknock'].split(',')) # we want ints
        grant_ports = []

        for r in group.rules:
            if r.ip_protocol == 'tcp' and r.from_port == r.to_port and r.from_port in group.tags['knockknock']:
                for g in r.grants:
                    if str(g) == str('%s/32' % ip):
                        grant_ports.append(int(r.from_port))
                        break

        ec2_groups.append({
            'id': group.id,
            'name': group.name,
            'all_ports': all_ports,
            'grant_ports': grant_ports,
            'boto_group': group
        })
        max_ec2_groups = max(max_ec2_groups, len(all_ports))
    return ec2_groups, max_ec2_groups

def validate_iam_user(user, password, account_id):
    s = requests.Session()
    r = s.get('https://%s.signin.aws.amazon.com/console' % str(account_id))

    data = {
        'redirect_uri': "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
        'client_id' : 'arn:aws:iam::015428540659:user/homepage', # this is the AWS console ARN, not yours
        'isIAMUser': "1",
        'mfaLoginFailure': "",
        'Action': "login",
        'RemainingExpiryPeriod': "",
        'account': account_id,
        'username': user,
        'password': password,
    }
    headers = {
        'Host': "signin.aws.amazon.com",
        'Referer': 'https://signin.aws.amazon.com/oauth',
    }
    r = s.post(
        'https://signin.aws.amazon.com/oauth',
        data=data,
        headers=headers,
        allow_redirects=False
    )
    return r.status_code == 302

if __name__ == "__main__":
    import os, sys

    app.debug = True

    try:
        conn = connect_to_region(os.getenv('AWS_DEFAULT_REGION', default="us-east-1"))
    except NoAuthHandlerFound:
        app.logger.error("AWS Connection failed.")
        app.logger.debug("Make sure you set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.")
        sys.exit(1)

    conn_iam = boto.connect_iam()
    account_id = conn_iam.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]

    app.logger.debug(
        "Connected to AWS: %s with key ID: %s",
        conn.DefaultRegionName,
        conn.get_params()['aws_access_key_id']
    )
    app.logger.debug(
        "account id: %s %s",
        account_id,
        conn_iam.get_account_alias()['list_account_aliases_response']['list_account_aliases_result']['account_aliases'][0]
    )

    app.config['account_id'] = account_id

    path = os.path.dirname(os.path.realpath(__file__))
    secret = ensure_secret(os.path.join(path, '.secret'), app)
    app.secret_key = secret
    app.config['ec2_conn'] = conn

    use_ssl = os.getenv('KNOCKKNOCK_SSL', default=False)
    if use_ssl:
        context='adhoc'
    else:
        context = None

    app.run(
        host='0.0.0.0',
        port=int(os.getenv('KNOCKKNOCK_PORT', default=5000)),
        ssl_context=context
    )

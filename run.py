from flask import Flask, redirect, render_template, request, session
import mysql.connector
import boto3
import os
import random

app = Flask(__name__)
app.secret_key=os.urandom(24)


mydb=mysql.connector.connect(host="localhost", user="root", password="", database="name_of_your_db")
mycursor=mydb.cursor()


ec2_client_minority=boto3.client('ec2', aws_access_key_id='', aws_secret_access_key='', region_name='')
ec2_client_hmc=boto3.client('ec2', aws_access_key_id='', aws_secret_access_key='', region_name='')
sns_client=boto3.client('sns', aws_access_key_id='', aws_secret_access_key='', region_name='')

security_group_id_minority_windowsproj1=''
security_group_id_minority_ubuntu=''
security_group_id_minority_IISMySql=''
security_group_id_hmc_appserver=''
security_group_id_hmc_windowssap=''

@app.route('/')
def input():
      return render_template('login.html')

@app.route('/login_validation', methods=['POST'])
def login_validation():  
      global otp    
      email=request.form.get('email')
      password=request.form.get('password')
      otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
      msg = f"Your OTP is: {otp}"
      response = sns_client.publish(
            TopicArn='',
            Message=msg,
            Subject='OTP Confirmation',
            MessageStructure='string',
            MessageAttributes={
                'email': {
                    'DataType': 'String',
                    'StringValue': email
                }
            }
        )
      mycursor.execute("""SELECT * FROM `name_of_table` WHERE `Email` LIKE '{}' AND `Password` LIKE '{}'""".format(email,password))
      users=mycursor.fetchall()          
      if len(users)>0:            
            session['ID']=users[0][0]
            return redirect('/otp')
      else:
            return redirect('/')      
@app.route('/otp')
def otp():
      if 'ID' in session:
            return render_template('otp.html')
      else:
            return redirect('/')
      
@app.route('/send_otp', methods=['POST'])
def send_otp():
     global otp
     form_otp=request.form.get('otp')
     if form_otp==otp:
          return redirect('/home')
     else:
          return redirect('/otp')

@app.route('/home')
def home():
      if 'ID' in session:
           return render_template('home.html')
      else:
           return redirect('/')

@app.route('/register')
def register():
      return render_template('register.html')
    
@app.route('/add_user', methods=['POST'])
def add_user():
	name = request.form.get('uname')
	email = request.form.get('uemail')
	password = request.form.get('upassword')
	mycursor.execute("""INSERT INTO `name_of_table` (`ID`,`Name`,`Email`,`Password`) VALUES (NULL,'{}','{}','{}')""".format(name,email,password))
	mydb.commit()
	return render_template("happy.html")

@app.route('/choose_project', methods=['GET', 'POST'])
def choose_project():
      name=request.form.get('project_name')
      if name=='minority':
            return redirect('/minority')
      elif name=='hmc':
            return redirect('/hmc')

@app.route('/minority')
def minority():
      if 'ID' in session:
            return render_template('minority.html')
      else:
            return redirect('/')

@app.route('/hmc')
def hmc():
      if 'ID' in session:
            return render_template('hmc.html')
      else:
            return redirect('/')

@app.route('/billing_minority', methods=['GET', 'POST'])
def billing_minority():
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
    else:
        start_date = request.args.get('start_date', '2024-02-01')
        end_date = request.args.get('end_date', '2024-02-09')
    try:
        client = boto3.client('ce', aws_access_key_id='', aws_secret_access_key='', region_name='us-east-1')
        response = client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[
                {
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE'
                }
            ]
        )

        # Extract and format billing information
        cost_breakdown = {}
        for result in response['ResultsByTime']:
            for group in result['Groups']:
                cost_breakdown[group['Keys'][0]] = {
                    'amount': group['Metrics']['BlendedCost']['Amount'],
                    'currency': group['Metrics']['BlendedCost']['Unit']
                }

        if 'ID' in session:
              return render_template('billing_minority.html', cost_breakdown=cost_breakdown)
        else:
              return redirect('/')
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/billing_hmc', methods=['GET', 'POST'])
def billing_hmc():
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
    else:
        start_date = request.args.get('start_date', '2024-02-01')
        end_date = request.args.get('end_date', '2024-02-09')
    try:
        client = boto3.client('ce', aws_access_key_id='', aws_secret_access_key='', region_name='us-east-1')
        response = client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date,
                'End': end_date
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[
                {
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE'
                }
            ]
        )

        # Extract and format billing information
        cost_breakdown = {}
        for result in response['ResultsByTime']:
            for group in result['Groups']:
                cost_breakdown[group['Keys'][0]] = {
                    'amount': group['Metrics']['BlendedCost']['Amount'],
                    'currency': group['Metrics']['BlendedCost']['Unit']
                }

        if 'ID' in session:
              return render_template('billing_minority.html', cost_breakdown=cost_breakdown)
        else:
              return redirect('/')
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_existing_ip_port_pairs_minority_windowsproj1():
    response = ec2_client_minority.describe_security_groups(GroupIds=[security_group_id_minority_windowsproj1])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

def get_existing_ip_port_pairs_minority_ubuntu():
    response = ec2_client_minority.describe_security_groups(GroupIds=[security_group_id_minority_ubuntu])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

def get_existing_ip_port_pairs_minority_IISMySql():
    response = ec2_client_minority.describe_security_groups(GroupIds=[security_group_id_minority_IISMySql])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

def get_existing_ip_port_pairs_hmc_appserver():
    response = ec2_client_hmc.describe_security_groups(GroupIds=[security_group_id_hmc_appserver])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

def get_existing_ip_port_pairs_hmc_windowssap():
    response = ec2_client_hmc.describe_security_groups(GroupIds=[security_group_id_hmc_windowssap])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

def get_security_group_rules_minority_windowsproj1():
    try:
        response = ec2_client_minority.describe_security_groups(GroupIds=[security_group_id_minority_windowsproj1])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []

def get_security_group_rules_minority_ubuntu():
    try:
        response = ec2_client_minority.describe_security_groups(GroupIds=[security_group_id_minority_ubuntu])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []

def get_security_group_rules_minority_IISMySql():
    try:
        response = ec2_client_minority.describe_security_groups(GroupIds=[security_group_id_minority_IISMySql])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []

def get_security_group_rules_hmc_appserver():
    try:
        response = ec2_client_hmc.describe_security_groups(GroupIds=[security_group_id_hmc_appserver])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []

def get_security_group_rules_hmc_windowssap():
    try:
        response = ec2_client_hmc.describe_security_groups(GroupIds=[security_group_id_hmc_windowssap])
        security_group = response['SecurityGroups'][0]
        inbound_rules = security_group.get('IpPermissions', [])
        return inbound_rules
    except Exception as e:
        print(f"Error fetching security group rules: {e}")
        return []


@app.route('/index_minority', methods=['GET', 'POST'])
def index_minority():
    existing_ip_port_pairs_minority_windowsproj1 = get_existing_ip_port_pairs_minority_windowsproj1()
    existing_ip_port_pairs_minority_ubuntu = get_existing_ip_port_pairs_minority_ubuntu()
    existing_ip_port_pairs_minority_IISMySql = get_existing_ip_port_pairs_minority_IISMySql()
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        action = request.form['action']
        port = request.form['protocol']
        server=request.form['server']
        if port == "rdp":
            port = 3389
        elif port == "ssh":
            port = 22
        try:
            if server=="windowsproj1":
                if action == 'add':
                    response = ec2_client_minority.authorize_security_group_ingress(
                    GroupId=security_group_id_minority_windowsproj1,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client_minority.revoke_security_group_ingress(
                    GroupId=security_group_id_minority_windowsproj1,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_minority_windowsproj1 = get_existing_ip_port_pairs_minority_windowsproj1()
            elif server=="ubuntu":
                if action == 'add':
                    response = ec2_client_minority.authorize_security_group_ingress(
                    GroupId=security_group_id_minority_ubuntu,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client_minority.revoke_security_group_ingress(
                    GroupId=security_group_id_minority_ubuntu,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_minority_ubuntu = get_existing_ip_port_pairs_minority_ubuntu()
            elif server=="IISMySql":
                if action == 'add':
                    response = ec2_client_minority.authorize_security_group_ingress(
                    GroupId=security_group_id_minority_IISMySql,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client_minority.revoke_security_group_ingress(
                    GroupId=security_group_id_minority_IISMySql,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_minority_IISMySql = get_existing_ip_port_pairs_minority_IISMySql()
        except Exception as e:
            message = f"Error: Invalid IP address format"

        if 'ID' in session:
              return render_template('index_minority.html', message=message, existing_ip_port_pairs_minority_windowsproj1=existing_ip_port_pairs_minority_windowsproj1, existing_ip_port_pairs_minority_ubuntu=existing_ip_port_pairs_minority_ubuntu, existing_ip_port_pairs_minority_IISMySql=existing_ip_port_pairs_minority_IISMySql)
        else:
              return redirect('/')
    if 'ID' in session:
         return render_template('index_minority.html', existing_ip_port_pairs_minority_windowsproj1=existing_ip_port_pairs_minority_windowsproj1, existing_ip_port_pairs_minority_ubuntu=existing_ip_port_pairs_minority_ubuntu, existing_ip_port_pairs_minority_IISMySql=existing_ip_port_pairs_minority_IISMySql)
    else:
         return redirect('/')
@app.route('/view_minority_windowsproj1')
def view_minority_windowsproj1():
      security_group_rules_minority_windowsproj1 = get_security_group_rules_minority_windowsproj1()
      if 'ID' in session:
            return render_template('view_minority_windowsproj1.html', security_group_rules_minority_windowsproj1=security_group_rules_minority_windowsproj1)
      else:
            return redirect('/')
@app.route('/view_minority_ubuntu')
def view_minority_ubuntu():
      security_group_rules_minority_ubuntu = get_security_group_rules_minority_ubuntu()
      if 'ID' in session:
            return render_template('view_minority_ubuntu.html', security_group_rules_minority_ubuntu=security_group_rules_minority_ubuntu)
      else:
            return redirect('/')
@app.route('/view_minority_IISMySql')
def view_minority_IISMySql():
      security_group_rules_minority_IISMySql = get_security_group_rules_minority_IISMySql()
      if 'ID' in session:
            return render_template('view_minority_IISMySql.html', security_group_rules_minority_IISMySql=security_group_rules_minority_IISMySql)
      else:
            return redirect('/')
@app.route('/index_hmc', methods=['GET', 'POST'])
def index_hmc():
    existing_ip_port_pairs_hmc_appserver = get_existing_ip_port_pairs_hmc_appserver()
    existing_ip_port_pairs_hmc_windowsapp = get_existing_ip_port_pairs_hmc_windowssap()
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        action = request.form['action']
        port = request.form['protocol']
        server=request.form['server']
        if port == "rdp":
            port = 3389
        elif port == "ssh":
            port = 22
        try:
            if server=="appserver":
                if action == 'add':
                    response = ec2_client_hmc.authorize_security_group_ingress(
                    GroupId=security_group_id_hmc_appserver,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client_hmc.revoke_security_group_ingress(
                    GroupId=security_group_id_hmc_appserver,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_hmc_appserver = get_existing_ip_port_pairs_hmc_appserver()
            elif server=="windowssap":
                if action == 'add':
                    response = ec2_client_hmc.authorize_security_group_ingress(
                    GroupId=security_group_id_hmc_windowssap,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address added successfully"
                elif action == 'remove':
                    response = ec2_client_hmc.revoke_security_group_ingress(
                    GroupId=security_group_id_hmc_windowssap,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                    message = "IP address removed successfully"
                existing_ip_port_pairs_hmc_windowsapp = get_existing_ip_port_pairs_hmc_windowssap()
            
        except Exception as e:
            message = f"Error: Invalid IP address format"

        if 'ID' in session:
              return render_template('index_hmc.html', message=message, existing_ip_port_pairs_hmc_appserver=existing_ip_port_pairs_hmc_appserver, existing_ip_port_pairs_hmc_windowsapp=existing_ip_port_pairs_hmc_windowsapp)
        else:
              return redirect('/')
    if 'ID' in session:
         return render_template('index_hmc.html', existing_ip_port_pairs_hmc_appserver=existing_ip_port_pairs_hmc_appserver, existing_ip_port_pairs_hmc_windowsapp=existing_ip_port_pairs_hmc_windowsapp)
    else:
         return redirect('/')
@app.route('/view_hmc_appserver')
def view_hmc_appserver():      
      security_group_rules_hmc_appserver = get_security_group_rules_hmc_appserver()
      if 'ID' in session:
           return render_template('view_hmc_appserver.html', security_group_rules_hmc_appserver=security_group_rules_hmc_appserver)
      else:
           return redirect('/')
@app.route('/view_hmc_windowssap')
def view_hmc_windowssap():
      security_group_rules_hmc_windowssap = get_security_group_rules_hmc_windowssap()
      if 'ID' in session:
           return render_template('view_hmc_windowssap.html', security_group_rules_hmc_windowssap=security_group_rules_hmc_windowssap)
      else:
           return redirect('/')
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

import requests
import click
import os
from xml.etree import ElementTree
from prettytable import PrettyTable
import xmltodict

# Production Config

# namecheap_api = "https://api.namecheap.com/xml.response"
# api_key = ""
# api_user = ""

# Sandbox Config

namecheap_api = "https://api.sandbox.namecheap.com/xml.response"
api_key = ""
api_user = ""

class API:
    def __init__(self):
        # Get Public IP
        r = requests.get("https://ifconfig.io/ip")
        client_ip = r.text.replace('\n', '')

        self.APIUser = api_user
        self.APIKey = api_key
        self.UserName = api_user
        self.ClientIP = client_ip
        self.APIUrl = namecheap_api

    def _payload(self, command):
        payload = {
            'ApiUser': self.APIUser,
            'ApiKey': self.APIKey,
            'UserName': self.UserName,
            'ClientIP': self.ClientIP,
            'Command': command,
        }
        return payload

    def _request(self, command, params):
        payload = self._payload(command)
        fullparams = {}
        fullparams.update(payload)
        fullparams.update(params)

        r = requests.post(self.APIUrl, params=fullparams)
        return r.text

    def _prettyprint(self, columns):
        x = PrettyTable()
        x.field_names = columns

        return x

class SSLApi(API):
    def __init__(self):
        API.__init__(self)

    def get_ssl_list(self):
        command = "namecheap.ssl.getList"
        params = {
            "ListType": "All",
            "PageSize": 100,
            "SortBy": "PURCHASEDATE"
        }
        results = self._request(command, params)
        results_dict = xmltodict.parse(results)

        columns = ["ID", "Host Name", "Type", "Purchase Date", "Expire Date", "Years", "Status"]
        table = self._prettyprint(columns)

        if results_dict['ApiResponse']['@Status'] == 'OK':
            ssl_certs_list = results_dict['ApiResponse']['CommandResponse']['SSLListResult']['SSL']
            cert_results = {}

            for item in ssl_certs_list:
                for key, value in item.items():
                    if key == "@CertificateID":
                        cert_results['id'] = value
                    if key == "@HostName":
                        cert_results['host'] = value
                    if key == "@SSLType":
                        cert_results['type'] = value
                    if key == "@PurchaseDate":
                        cert_results['purchase'] = value
                    if key == "@ExpireDate":
                        cert_results['expire'] = value
                    if key == "@Years":
                        cert_results['years'] = value
                    if key == "@Status":
                        cert_results['status'] = value
                table.add_row([cert_results.get('id'), cert_results.get('host'), cert_results.get('type'), cert_results.get('purchase'),
                     cert_results.get('expire'), cert_results.get('years'), cert_results.get('status')])
            # return pretty table
            return table
        else:
            error = {}
            for k in results_dict['ApiResponse']['Errors']:
                error["error_code"] = results_dict['ApiResponse']['Errors']['Error']['@Number']
                error["error_msg"] = results_dict['ApiResponse']['Errors']['Error']['#text']
            return error

    def create_ssl_cert(self, years, type):
        command = "namecheap.ssl.create"
        params = {
            "Years": years,
            "Type": type
        }
        results = self._request(command, params)
        results_dict = xmltodict.parse(results)

        if results_dict['ApiResponse']['@Status'] == 'OK':
            ssl_certs_list = results_dict['ApiResponse']['CommandResponse']['SSLCreateResult']
            order_results = {}
            for key, value in ssl_certs_list.items():
                if key == '@IsSuccess':
                    order_results['order_status'] = value
                if key == '@OrderId':
                    order_results['orderid'] = value
                if key == '@TransactionId':
                    order_results['transactionid'] = value
                if key == '@ChargedAmount':
                    order_results['chargedamount'] = value
                if key == 'SSLCertificate':
                    for k in value:
                        if k == '@CertificateID':
                            order_results['certificateid'] = value[k]
                        if k == '@Created':
                            order_results['created_date'] = value[k]
                        if k == '@SSLType':
                            order_results['ssl_type'] = value[k]
                        if k == '@Years':
                            order_results['years'] = value[k]
                        if k == '@Status':
                            order_results['cert_status'] = value[k]

            # Purchase Table
            columns = ["Order ID", "Transaction ID", "Charged Amount", "Order Status"]
            purchase_table = self._prettyprint(columns)

            purchase_table.add_row([order_results.get('orderid'), order_results.get('transactionid'), order_results.get('chargedamount') ,order_results.get('order_status')])

            # Certificate Table
            columns = ["Cert ID", "Created Date", "SSL Type", "Years", "Status"]
            cert_table = self._prettyprint(columns)

            cert_table.add_row(
                [order_results.get('certificateid'), order_results.get('created_date'), order_results.get('ssl_type'),
                 order_results.get('years'), order_results.get('cert_status')])

            # return pretty table
            return purchase_table, cert_table
        else:
            error = {}
            for k in results_dict['ApiResponse']['Errors']:
                error["error_code"] = results_dict['ApiResponse']['Errors']['Error']['@Number']
                error["error_msg"] = results_dict['ApiResponse']['Errors']['Error']['#text']
            return error

    # Activate SSL Cert
    def activate_ssl_cert(self, issuetype, certid, csr, email, path):
        if issuetype == 'activate':
            command = "namecheap.ssl.activate"
        if issuetype == 'reissue':
            command = "namecheap.ssl.reissue"
        params = {
            "CertificateID": certid,
            "CSR": csr,
            "AdminEmailAddress": email,
            "WebServerType": "nginx",
            "ApproverEmail": email,
            "DNSDCValidation": True,
        }
        results = self._request(command, params)
        results_dict = xmltodict.parse(results)

        if results_dict['ApiResponse']['@Status'] == 'OK':
            ssl_activation_list = results_dict['ApiResponse']['CommandResponse']['SSLActivateResult']
            activate_results = {}
            for key, value in ssl_activation_list.items():
                if key == '@ID':
                    activate_results['certid'] = value
                if key == '@IsSuccess':
                    activate_results['success'] = value
                if key == 'DNSDCValidation':
                    for k,v in value.items():
                        if k == '@ValueAvailable':
                            activate_results['dns_validation'] = v
                        if k == 'DNS':
                            for x,y in v.items():
                                if x == '@domain':
                                    activate_results['domain'] = y
                                if x == 'HostName':
                                    activate_results['cname_host'] = y
                                if x == 'Target':
                                    activate_results['cname_target'] = y
            # Activation Table
            columns = ["Cert ID", "DNS Validation", "Domain", "CNAME Host", "CNAME Target", "Activation Status"]
            activation_table = self._prettyprint(columns)

            activation_table.add_row([activate_results.get('certid'), activate_results.get('dns_validation'), activate_results.get('domain'),
                 activate_results.get('cname_host'),
                 activate_results.get('cname_target'), activate_results.get('success')])

            # Check whether to save dns verification files
            if path:
                cnamehost_filename = "%s%s" % (activate_results.get('domain'), "_cname_host.txt")
                cnamehost_file= os.path.join(path, cnamehost_filename)

                cnametarget_filename = "%s%s" % (activate_results.get('domain'), "_cname_target.txt")
                cnametarget_file = os.path.join(path, cnametarget_filename)

                if os.path.exists(cnamehost_filename):
                    print ("Saving file: %s" % (cnamehost_filename))
                    f = open(cnamehost_file, "w")
                    f.write(activate_results.get('cname_host'))
                    f.close()
                else:
                    print("Saving file: %s" % (cnamehost_filename))
                    f = open(cnamehost_file, "x")
                    f.write(activate_results.get('cname_host'))
                    f.close()
                if os.path.exists(cnametarget_filename):
                    print("Saving file: %s" % (cnametarget_filename))
                    f = open(cnametarget_file, "w")
                    f.write(activate_results.get('cname_target'))
                    f.close()
                else:
                    print("Saving file: %s" % (cnametarget_filename))
                    f = open(cnametarget_file, "x")
                    f.write(activate_results.get('cname_target'))
                    f.close()

            # return pretty table
            return activation_table
        else:
            error = {}
            for key, value in results_dict['ApiResponse']['Errors'].items():
                error["error_code"] = value['@Number']
                error["error_msg"] = value['#text']
            return error

# CLI

@click.group()
def main():
    """
    SSL:
    namecheap.py ssl <option>
    """
    pass

@main.command()
@click.option('--method', help='Options: create, list, activate')
@click.option('--type', help='Options: wildcard')
@click.option('--csr', help='Options: Path to CSR file')
@click.option('--email', help='Options: Email')
@click.option('--certid', help='Options: Certificate ID')
@click.option('--issuetype', help='Options: activate or reissue')
@click.option('--outputfile', help='Optional bool to save dns verification files')
def ssl(method, type, csr, email, certid, issuetype, outputfile):
    """
    List:
    namecheap.py ssl --method list

    Create:
    namecheap.py ssl --method create --type wildcard

    Activation:
    namecheap.py ssl --method activate --csr <csr file path> --email "<email address>" --certid <cert id> --issuetype <activate/reissue> --outputfile <bool>
    """
    if method == 'list':
        s = SSLApi()
        click.echo(s.get_ssl_list())
    elif method == 'create':
        if type == 'wildcard':
            s = SSLApi()
            # Hardcode to match company policy
            order, cert = s.create_ssl_cert(1, 'PositiveSSL Wildcard')
            print ("Order Status:")
            print (order)
            print ("Cert Status:")
            print (cert)
        else:
            print_help()
    elif method == 'activate':
        if None not in (csr, certid, email, issuetype):
            if issuetype == 'activate' or issuetype == 'reissue':
                try:
                    f = open(csr)
                    csr_content = f.read()
                except IOError:
                    print ("Error: File does not appear to exist..")

                # If true, set current working directory
                if outputfile:
                    path = os.getcwd()

                s = SSLApi()
                print (s.activate_ssl_cert(issuetype, certid, csr_content, email, path))
            else:
                print("Error: Issue type not specified.")
                print_help()
        else:
            print("Error: Invalid Options")
            print_help()
    else:
        print_help()


def print_help():
    ctx = click.get_current_context()
    click.echo(ctx.get_help())
    ctx.exit()

if __name__ == '__main__':
    main()

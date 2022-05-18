# Get SSL certificate details from URL and push informations to Azure Log Analytics Workspace
# https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api

import json
import requests
import datetime
import hashlib
import hmac
import base64
import socket
import ssl

# Update the customer ID to your Log Analytics workspace ID
customer_id = ''

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = ""

# The log type is the name of the event that is being submitted
log_type = 'CertificateExpiration'

# Update the URLs to monitor SSL certificate
target_urls = [
    "website1.local",
    "website2.local"
]

def ssl_expiration_datetime(hostname):
    ssl_dateformat = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.settimeout(5.0)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    # Python datetime object
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)

json_data = []

if __name__ == "__main__":
    for value in target_urls:
        now = datetime.datetime.now()
        try:
            expire = ssl_expiration_datetime(value)
            diff = expire - now
            fields = {
                "ExpiryDays": diff.days,
                "ExpiryDate": expire.strftime("%Y-%m-%d, %H:%M:%S"),
                "TargetUrl": value
            }
            json_data.append(fields)
        except Exception as e:
            print (e)

body = json.dumps(json_data)

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))


# Post results to Azure Log Analytics Workspace
post_data(customer_id, shared_key, body, log_type)
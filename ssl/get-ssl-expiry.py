# Get SSL certificate details from URL list
# Execute the script then pass URLs like this when asked :
# webiste1.local, website2.local, website3.local

import datetime
import socket
import ssl
from tabulate import tabulate


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

def results():
    target_urls = [item for item in input("Enter the list of URLs as a comma separated list: \n").split(", ")]
    data = [["Domain", "Expiry Date", "Remaining Days"],]
    if __name__ == "__main__":
        for value in target_urls:
            now = datetime.datetime.now()
            try:
                expire = ssl_expiration_datetime(value)
                diff = expire - now
                fields = [
                    value,
                    expire.strftime("%Y-%m-%d, %H:%M:%S"),
                    diff.days]
                data.append(fields)
            except Exception as e:
                print (e)
    print(tabulate(data,headers='firstrow'))

results()
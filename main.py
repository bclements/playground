import requests
import os
import sys
import argparse
import re
import pandas as pandabear

vt_apikey = os.environ.get('VT_APIKEY')


def validate_target(target):
    '''
    validate_target: Function to check if the supplied target is either a valid hostname or ip address
    vars:
        target: The text s
    '''
    validIpAddressRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    validHostnameRegex = "^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"
    if re.match(validIpAddressRegex, target):
        return {'type': 'ip-address', 'param': 'ip'}
    elif re.match(validHostnameRegex, target):
        return {'type': 'domain', 'param': 'domain'}
    else:
        print("Invalid Domain name or Ip address")
        return sys.exit(2)


def get_target_data(target, target_type):
    '''
      get_target_data: Function to retrieve report data from virustotal.
        vars:
            target: ip address or domain name to retrieve data about
            target_type: dictionary containing the type of target and the uri parameter

        returns json data retrieved from virustotal url
    '''
    vt_url = 'https://www.virustotal.com/vtapi/v2/{0}/report?apikey={1}&{2}={3}'.format(target_type['type'], vt_apikey, target_type['param'], target)

    try:
        req = requests.get(url=vt_url)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)

    data = req.json()
    return data


def main():
    '''
    VirusTotal Simple Report Client
    '''
    parser = argparse.ArgumentParser(
        description='Retrieve Virtual Total Reports by Domain/hostname or IP Address')
    parser.add_argument('target', metavar='TARGET', type=str, nargs='?',
                        help='The domain or ip address you would like to retrieve a report on')

    args = vars(parser.parse_args())
    if not args['target']:
        print("Missing Domain or IP Address to report on")
        return sys.exit(2)

    target = args['target']
    target_type = validate_target(target)

    data = get_target_data(target, target_type)

    # Print out one of the json datasets as an example.
    print(pandabear.DataFrame(data['detected_urls']))


if __name__ == '__main__':
    main()

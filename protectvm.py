#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json
import re
import time

# The purpose of this script is to facilitate VM Protection in RP4VMs
# The script exclusively uses the new RESTful API in RP4VMs 5.3
# Author(s) - Idan Kentor <idan.kentor@dell.com>
# Version 1 - August 2020
# Version 2 - December 2020

# Copyright [2020] [Idan Kentor]

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to perform ad-hoc VM backup in PowerProtect')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='RP4VMs Plugin Server DNS name or IP')
    parser.add_argument('-file', '--credsfile', required=True,
                        action='store', help='Path to credentials file')
    parser.add_argument('-a', '--action', required=True, choices=['list', 'protect'],
                        help='Choose to list all candidate VMs or to protect a VM')
    parser.add_argument('-n', '--name', required=('protect' in sys.argv),
                        action='store',
                        default=None, help='The name of the VM to protect')
    parser.add_argument('-cl', '--rpvmcluster', required=False, action='store',
                        default=None, help='Optionally specify the RP4VMs cluster to protect the VM')
    parser.add_argument('-nmonitor', '--no-monitor', required=False, action='store_true', dest='nmonitor',
                        default=False, help='Optionally prevents monitoring of protection process')
    args = parser.parse_args()
    return args

def get_creds(credsfile, uri):
    # Gets and validates credentials
    file = open(credsfile, 'r')
    credstring = file.read().rstrip()
    file.close()
    user, password = credstring.split(' ')
    suffixurl = "/version"
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.get(uri, headers=headers, auth=(user, password),verify=False)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as err:
        print('Error Connecting to {}: {}'.format(uri, err))
        sys.exit(1)
    except requests.exceptions.Timeout as err:
        print('Connection timed out {}: {}'.format(urllib3, err))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
        sys.exit(1)
    if (response.status_code != 200):
        raise Exception('Invalid credentials, code: {}, body: {}'.format(
            response.status_code, response.text))
    return user, password

def get_candidates(uri, user, password, name, rpvmcluster):
    # Gets candidate VMs for replication
    suffixurl = "/vms/protect/candidates"
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    filter = ''
    bfilter = filter
    if name != None:
        filter += name
    params = {'vms': filter}
    try:
        response = requests.get(uri, headers=headers, params=params, auth=(user, password), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    exactresult = response.json()
    vms = []
    if (response.status_code == 200 and response.json() == [] and name != None):
        params = {'vms': bfilter}
        try:
            response = requests.get(uri, headers=headers, params=params, auth=(user, password), verify=False)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
        if (response.status_code != 200):
            raise Exception('Failed to query {}, code: {}, body: {}'.format(
			        uri, response.status_code, response.text))
        for vm in response.json():
            if re.match(name.lower(), vm['name'].lower()):
                vms.append(vm)
    if vms:
        return check_rpvmcluster(vms, rpvmcluster)
    return check_rpvmcluster(exactresult, rpvmcluster)

def check_rpvmcluster(vmlist, rpvmcluster):
    # Check if a VM can be protected by a specific RP4VMs cluster
    if rpvmcluster is None:
        return vmlist
    else:
        vms = []
        for vm in vmlist:
             if re.match(rpvmcluster.lower(), vm['rpClusterName'].lower()):
                 vms.append(vm)
    return vms

def get_defaults(uri, user, password, vmname, rpvmcluster):
    # Gets recommended replication parameters
    suffixurl = "/vms/protect/defaults"
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps({
        'vm' : '{}'.format(vmname),
	    'rpCluster' : '{}'.format(rpvmcluster)
	    })
    try:
        response = requests.post(uri, headers=headers, data=payload, auth=(user, password), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    return response.json()

def protect_vm(uri, user, password, protectparams):
    # Protects a specific VM
    suffixurl = "/vms/protect"
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    protectparams=json.dumps(protectparams, indent=4)
    try:
        response = requests.post(uri, headers=headers, data=protectparams, auth=(user, password), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    return response.json()['id']

def monitor_activity(uri, user, password, transactionid):
    # Monitors an activity by its transaction ID
    timeout = 300 # 5 minutes timeout
    interval = 5 # 10 seconds interval
    suffixurl = "/transactions/"
    uri += suffixurl + str(transactionid)
    start = time.time()
    headers = {'Content-Type': 'application/json'}
    while True:
        if (time.time() - start) > timeout:
            break
        try:
            response = requests.get(uri, headers=headers, auth=(user, password), verify=False)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
        if (response.status_code != 200):
            print('Failed to query {}, code: {}, body: {}'.format(
                uri, response.status_code, response.text))
            return None
        print('---> Transaction {} {}'.format(transactionid, response.json()['status']))
        if response.json()['status'] == 'COMPLETED':
            return response.json()['status']
        time.sleep(interval)
    return 'TIMEOUT'

def main():
    apiendpoint = "/api/v1"
    args = get_args()
    server, credsfile, name = args.server, args.credsfile, args.name
    action, nmonitor, rpvmcluster = args.action, args.nmonitor, args.rpvmcluster
    uri = "https://{}{}".format(server, apiendpoint)
    user, password = get_creds(credsfile, uri)
    print("\n")
    print("-> Credentials check successful\n")
    print("-> Getting VM candidates\n")
    vms = get_candidates(uri, user, password, name, rpvmcluster)
    if len(vms) == 0:
            print('VM could not be found')
    if (action == 'list'):
        for vm in vms:
            print("---------------------------------------------------------")
            print("VM ID:", vm["id"])
            print("VM Name:", vm["name"])
            print("vCenter Name:", vm["vcName"])
            print("vCenter ID:", vm["vcId"])
            print("RP4VMs Cluster Name:", vm["rpClusterName"])
            print("RP4VMs Cluster ID:", vm["rpClusterId"])
            print()
    elif (len(vms) > 1):
        print ("VM Name {} yielded in more than 1 result".format(name))
        print("Narrow down the results using the --action list paramater")
    elif (len(vms) == 1):
        print("-> Protecting VM:", vms[0]["name"], "\n")
        protectparams = get_defaults(uri, user, password, vms[0]["name"], vms[0]["rpClusterName"])
        transactionid = protect_vm(uri, user, password, protectparams)
        if (transactionid is None):
            next
        elif (not nmonitor):
            print("-> VM protection initiated, monitoring\n")
            monitor_activity(uri, user, password, transactionid)
        elif (nmonitor):
            print("-> VM protection initiated\n")

if __name__ == "__main__":
    main()

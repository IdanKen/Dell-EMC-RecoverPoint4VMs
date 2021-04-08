#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json
import re
import time

# The purpose of this script is to facilitate backup/restore of settings in RP4VMs
# The script exclusively uses the new RESTful API in RP4VMs 5.3
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - April 2021

# Copyright [2021] [Idan Kentor]

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
        description='Script to backup and restore settings in RecoverPoint for VMs')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='RP4VMs Plugin Server DNS name or IP')
    parser.add_argument('-cfile', '--credsfile', required=True,
                        action='store', help='Path to credentials file')
    parser.add_argument('-a', '--action', required=True, choices=['backup', 'restore'],
                        help='Choose to backup or restore settings')
    parser.add_argument('-file', '--file', required=True,
                        action='store', help='Path to file for backup/restore')
    parser.add_argument('-vc', "--vcenter", required=('new-vc' in sys.argv), action='store',
                        help='Provide vCenter DNS name or IP')
    parser.add_argument('-cpairs', '--clusterpairs', required=False, action='store',
                        help='Provide RP4VMs cluster pairing in format of oldcl1,newcl1,oldcl12,newcl2')
    parser.add_argument('-nmonitor', '--no-monitor', required=False, action='store_true', dest='nmonitor',
                        default=False, help='Optionally prevents monitoring of protection process')
    args = parser.parse_args()
    return args

def init_rest_call(calltype, uri, user, password, payload=None):
    # BETA refactor call to initiate rest calls
    code = 200
    headers = {'Content-Type': 'application/json'}
    verify = False
    try:
        if calltype.lower() == "get":
            response = requests.get(uri, headers=headers, auth=(user, password), verify=verify)
        else:
            response = requests.calltype(uri, headers=headers, data=payload , auth=(user, password), verify=verify)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as err:
        print('Error Connecting to {}: {}'.format(uri, err))
        sys.exit(1)
    except requests.exceptions.Timeout as err:
        print('Connection timed out {}: {}'.format(urllib3, err))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != code):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(uri, response.status_code, response.text))
    return response.json()

def get_clusters(uri, user, password):
    # Gets list of RP4VMs clusters
    headers = {'Content-Type': 'application/json'}
    suffix = "/rp-clusters"
    uri += suffix
    try:
        response = requests.get(uri, headers=headers, auth=(user, password), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    return response.json()

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

def backup_general(uri, user, password, file):
    # Backs up general config data like CGs, VMs, Group Sets, VCs, etc.
    suffixlist = "/groups", "/vms", "/group-sets", "/vcs", "/licenses", "/rp-clusters"
    headers = {'Content-Type': 'application/json'}
    fileh = open(file, 'w')
    for suffix in suffixlist:
        nuri = uri + suffix
        try:
            response = requests.get(nuri, headers=headers, auth=(user, password), verify=False)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
        if (response.status_code != 200):
            raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
        if (suffix == "/groups"):
            groups = response.json()
        fileh.write(response.request.method + ' ' + response.url + "\n")
        fileh.write(str(response.json()))
        fileh.write("\nEND\n")
    fileh.close()
    return groups

def get_all_copies(groups):
    # Get all copies for all CGs
    copies = []
    for group in groups:
        for copy in group["copyIds"]:
            copies.append("/groups/{}/copies/{}".format(group["name"], copy))
    return copies

def load_json(data):
    # Align data and convert to JSON
    if (isinstance(data, dict)):
        for copyid in data:
            data[copyid] = data[copyid].replace("\'", "\"")
            data[copyid] = data[copyid].replace("True", "true")
            data[copyid] = data[copyid].replace("False", "false")
            data[copyid] = json.loads(data[copyid])
    else:
        data = data.replace("\'", "\"")
        data = data.replace("True", "true")
        data = data.replace("False", "false")
        data = json.loads(data)
    return data

def backup_groups(uri, user, password, file, copies):
    # Backs up per-CG and per-Copy specific settings
    headers = {'Content-Type': 'application/json'}
    suffixlist = "/", "/journals", "/re-ip"
    payload = None
    method = "GET"
    fileh = open(file, 'a')
    for copy in copies:
        for suffix in suffixlist:
            nuri = uri + copy + suffix
            response = init_rest_call(method, nuri, user, password, payload)
            fileh.write(method + ' ' + nuri + "\n")
            fileh.write(str(response))
            fileh.write("\nEND\n")
    fileh.close()
    return None

def validate_cluster_pairs(cpairs):
    # Validates the cluster pairs parameter
    if cpairs:
        if (cpairs.find(',') < 1):
            clusters = get_clusters(uri, user, password)
            print("Incorrect format of the cluster pairs parameter, existing")
            sys.argv(1)
        else:
            cpairs = cpairs.split(',')
            if (len(cpairs) % 2 != 0):
                print("Incorrect format of the cluster pairs parameter, existing")
                sys.argv(1)
            else:
                return cpairs
    else:
        return None

def extract_backup_data(file):
    # Extract backup information from backup file
    fileh = open(file, 'r')
    data = {}
    copies = {}
    copyparams = 'copies', 'journals', 're-ip'
    for param in copyparams:
        copies[param] = {}
    for line in fileh:
        if line.startswith("GET"):
            check = re.search("/v1/(.*)$", line).groups()[0]
            if "copies" in check:
                match = re.search("/groups/(.*)/copies/(\w+)/(.*?)$", line)
                group, copyid = match.groups()[0], match.groups()[1]
                if not match.groups()[2]:
                    check = "copies"
                else:
                    check = match.groups()[2]
        elif line.startswith("END"):
            check = None
        else:
            if check in copyparams:
                copies[check][copyid] = line
            else:
                data[check] = line
    fileh.close()
    return data, copies

def merge_group_data(groups, vms, copysettings, journals, reip):
    # Add protected VMs to the their respective CG
    for group in groups:
        vmlist = []
        prodvmcounter = 0
        copylist = []
        for vm in vms:
            if vm["groupId"] == group["id"]:
                vmlist.append(vm)
        group.update({'vms': [vmlist]})
        for vm in vmlist:
                if "PRODUCTION" in vm["role"]:
                    prodvmcounter += 1
        group.update({'prodvmcount': prodvmcounter})
        for copyid in journals:
            if (group["id"] in copyid):
                group.update({'journals': journals[copyid]})
        for copyid in reip:
            if (group["id"] in copyid):
                group.update({'re-ip': reip[copyid]})
        for copyid in copysettings:
            if (group["id"] in copyid):
                copylist.append(copysettings[copyid])
        group.update({'copies': '{}'.format(json.dumps(copylist))})
    return groups

def check_rep_topology(group):
    if len(group["copyIds"]) == 2:
        return True
    else:
        return False

def determine_rpcluster(uri, user, password, group, cpairs):
    # Gets the desired RP4VMs cluster
    clusters = get_clusters(uri, user, password)
    if cpairs:
        for counter in range(len(cpairs)-1):
            if group["prodRpClusterName"] == cpairs[counter]:
                rpcluster = cpairs[counter+1]
            else:
                counter += 1
    else:
            if clusters[0]["isRegistered"]:
                rpcluster = clusters[0]["name"]
            else:
                rpcluster = clusters[1]["name"]
    return rpcluster

def get_candidates(uri, user, password, name):
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
            if re.match(name.lower(),vm['name'].lower()):
                vms.append(vm)
    if vms:
        return vms
    return exactresult

def determine_journal(group):
    # Checks if non-default journal size is used for replica copy
    totaljournal = 0
    for journal in group["journals"]:
        if journal["copyId"] != group["prodCopyId"]:
            totaljournal += journal["sizeInMB"]
    return totaljournal

def exclude_disks(defaults, group):
    # Determines whether to exclude disks or not
    excludeddisks = {}
    for vm in group["vms"][0]:
        for disk in vm["vmdks"]:
            if not disk["included"]:
                excludeddisks[vm["id"]] = []
                excludeddisks[vm["id"]].append(disk["path"])
    if len(excludeddisks) == 0:
        return defaults
    else:
        if len(group["vms"] == 1):
            for disk in defaults["protectedVmdks"]:
                for excludeddisk in excludeddisk[defaults["vm"]]:
                    if disk == excludeddisk:
                        defaults["protectedVmdks"].remove(disk)
        else:
            for vms in defaults["vms"]:
                for disk in vm["protectedVmdks"]:
                    for excludeddisk in excludeddisk[vm["vm"]]:
                        if disk == excludeddisk:
                            vm["protectedVmdks"].remove(disk)
    return defaults

def get_defaults(uri, user, password, group, rpcluster):
    # Gets recommended replication parameters
    suffixurl = "/vms/protect/defaults"
    suffixurl2 = "/vms/protect-to-single-group/defaults"
    vms = group["vms"]
    headers = {'Content-Type': 'application/json'}
    if group["prodvmcount"] == 0:
        print("no VMs found for group: {}, exiting".format(group["name"]))
        sys.exit(1)
    else:
        vmlist = []
        vmdict = {}
        for vm in vms[0]:
            if "PRODUCTION" in vm["role"]:
                if group["prodvmcount"] == 1:
                    payload = json.dumps({
                        'vm' : '{}'.format(vms[0][0]["name"]),
	                    'rpCluster' : '{}'.format(rpcluster)
	                })
                else:
                    vmdict = {"vm": vm["name"]}
                    vmlist.append(vmdict)
                    suffixurl = suffixurl2
        if vmlist:
            payload = {}
            payload['vms'] = vmlist
            payload['rpCluster'] = rpcluster
            payload = json.dumps(payload)
    try:
        uri += suffixurl
        response = requests.post(uri, headers=headers, data=payload, auth=(user, password), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}, payload: {}'.format(
				uri, response.status_code, response.text, payload))
    return response.json()

def apply_policy(defaults, group, defaultjournal, defaultrpo):
    # Applies policy to the defaults payload
    journal = determine_journal(group)
    if group["prodvmcount"] == 1:
        recommendation = defaults["groupConfiguration"]
    else:
        recommendation = defaults
    group["copies"] = json.loads(group["copies"])
    for copy in group["copies"]:
        if "REPLICA" in copy["copyRole"]:
            if copy["rpoInSeconds"] != 25:
                    recommendation["copies"][0]["rpoInSeconds"] = copy["rpoInSeconds"]
                    if copy["syncReplication"]:
                        recommendation["copies"][0]["syncReplication"] = True
                        recommendation["copies"][0]["rpoInSeconds"] = 0

    if int(journal) != defaultjournal:
            recommendation["copies"][0]["journalSizeInMB"] = journal
    else:
        if int(journal) != defaultjournal:
                recommendation["copies"][0]["journalSizeInMB"] = journal
    if group["prodvmcount"] == 1:
        recommendation["name"] = group["name"]
        defaults["groupConfiguration"] = recommendation
    else:
            defaults = recommendation
            defaults["groupName"] = group["name"]
    defaults = exclude_disks(defaults, group)
    return defaults

def protect_vm(uri, user, password, defaults):
    # Protects a specific VM
    suffixurl = "/vms/protect"
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    defaults=json.dumps(defaults, indent=4)
    try:
        response = requests.post(uri, headers=headers, data=defaults, auth=(user, password), verify=False)
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

def get_grouppolicy(uri, user, password, groupname):
    # Gets CG name and group policy from current CG
    groupuri = "{}/groups/{}".format(uri, groupname)
    payload = None
    grouppolicy = init_rest_call("GET", groupuri, user, password, payload)
    uri += "/vms"
    vmlist = init_rest_call("GET", uri, user, password, payload)
    return grouppolicy, vmlist

def get_vmsequence_by_vmname(vmname, group):
    # Gets VM replication ID per VM name from backup
    for vm in vms[0]:
        if vm["name"] == vmname:
           vmrepid = vm["vmReplicationId"]
    for repid in group["vmsStartupSequence"]:
        if repid == vmrepid:
            return group[repid]

def config_startup_sequence(groupname, grouppolicy, vmlist):
    # Applies the former startup sequence
    vms = []
    vmstartupseq2 = {}
    for vmrepid in grouppolicy["vmsStartupSequence"]:
        for vm in vms:
            vmstartupseq2[vmrepid] = get_vmsequence_by_vmname(vm, group)
            vmstartupseq2[vmrepid][vmReplicationId] = vmrepid
    if vmstartupseq2:
        grouppolicy["vmsStartupSequence"] = vmstartupseq2
    return grouppolicy

def main():
    apiendpoint = "/api/v1"
    defaultjournal = 10240
    defaultrpo = 25
    args = get_args()
    server, credsfile, file = args.server, args.credsfile, args.file
    action, nmonitor, cpairs = args.action, args.nmonitor, args.clusterpairs
    uri = "https://{}{}".format(server, apiendpoint)
    if (action == 'backup'):
        user, password = get_creds(credsfile, uri)
        print("-> Credentials check successful\n")
        groups = backup_general(uri, user, password, file)
        copies = get_all_copies(groups)
        backup_groups(uri, user, password, file, copies)
        print("-> Configuration backed up successfully\n")
    else:
        cpairs = validate_cluster_pairs(cpairs)
        data, copies = extract_backup_data(file)
        print("-> Running pre-restore checks\n")
        groups = load_json(data["groups"])
        copysettings = load_json(copies["copies"])
        journals = load_json(copies["journals"])
        reip = load_json(copies["re-ip"])
        vms = load_json(data["vms"])
        clusters = load_json(data["rp-clusters"])
        user, password = get_creds(credsfile, uri)
        print("-> Credentials check successful\n")
        currentclusters = get_clusters(uri, user, password)
        if len(clusters) != len(currentclusters):
            print("different system size, existing...")
            sys.exit(1)
        groups = merge_group_data(groups, vms, copysettings, journals, reip)
        for group in groups:
            if check_rep_topology(group):
                print("-> Operating on Group:", group["name"])
                print("---> Pre-validation passed")
                rpcluster = determine_rpcluster(uri, user, password, group, cpairs)
                defaults = get_defaults(uri, user, password, group, rpcluster)
                defaults = apply_policy(defaults, group, defaultjournal, defaultrpo)
                transactionid = protect_vm(uri, user, password, defaults)
                if (transactionid is None):
                    print("Could not protect VMs in group:{}, existing...".format(group["name"]))
                    sys.exit(2)
                elif (not nmonitor):
                    print("---> VM protection initiated, monitoring\n")
                    monitor_activity(uri, user, password, transactionid)
                elif (nmonitor):
                    print("---> VM protection initiated")
                print("---> Configuring orchestration settings")
                grouppolicy, vmlist = get_grouppolicy(uri, user, password, group["name"])
                grouppolicy = config_startup_sequence(group["name"], grouppolicy, vmlist)
                print("---> Group {} created and configured\n".format(group["name"]))

if __name__ == "__main__":
    main()

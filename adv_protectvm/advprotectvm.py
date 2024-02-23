#!/usr/bin/env python3

import argparse
import json
import time
import base64
import urllib3
import requests

# The purpose of this script is to facilitate advanced VM protection in RP4VMs.
# The script exclusively uses the new RESTful API in RP4VMs 5.3
# Author(s) - Idan Kentor <idan.kentor@dell.com>
# Version 1 - January 2024

# Copyright [2024] [Idan Kentor]

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
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Scripts advanced VM Protection in RecoverPoint for VMs',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
        Examples:
        - Protect VMs:
        python advprotectvm.py -file vms.json
        - Protect VMs by a specific RP4VMs cluster:
        python advprotectvm.py -file vms.json -cl NY-CL1
        - Protect VMs on a specific plugin server:
        python advprotectvm.py -file vms.json -s pluginserver.idan.dell.com
        - Protect VMs but do not monitor protection preparation task:
        python advprotectvm.py -file vms.json -a protect -nmonitor
        ''')
    parser.add_argument('-file', '--vm-config-file', required=True,
                        dest='config_file',
                        action='store', help='Path to VM config file')
    parser.add_argument('-cl', '--rpvmcluster', required=False, action='store',
                        dest='rpvm_cluster',
                        default=None,
                        help='Optionally specify the RP4VMs cluster')
    parser.add_argument('-s', '--server', required=False,
                        action='store',
                        help='Optionally specify RP4VMs Plugin Server DNS/IP')
    parser.add_argument('-nmonitor', '--no-monitor', required=False,
                        action='store_true', dest='no_monitor',
                        default=False,
                        help='Optionally prevents protection monitoring')
    args = parser.parse_args()
    return args


def read_config(config_file, rpvm_cluster, server):
    """Parses and checks the JSON config file"""
    try:
        with open(config_file, 'r', encoding="utf-8") as file_handle:
            config = json.load(file_handle)
            file_handle.close()
            config = config["VmsToProtect"]
    except (IOError, json.decoder.JSONDecodeError) as error:
        print(f"\033[91m\033[1m->Cannot parse JSON config file: \
                {error} \033[0m")
        raise SystemExit(1) from error
    for index, vm in enumerate(config):
        bad_vm_record = False
        for key in list(vm):
            if not config[index][key] or key.startswith('_comment'):
                del config[index][key]
        if not all(key in vm for key in ("pluginServerIpOrFqdn", "vmName",
                                         "rpvmCluster")):
            print(f"\033[91m\033[1m->Missing required parameters for VM # \
                  {index + 1}, skipping...\033[0m")
            bad_vm_record = True
        if not bad_vm_record:
            if not vm.get("credentialsFile"):
                if not vm.get("vcUser") and not vm.get("vcPassB64"):
                    print(f"\033[91m\033[1m->Missing credentials for VM # \
                          {index + 1}, skipping...\033[0m")
                    bad_vm_record = True
            if server:
                if vm["pluginServerIpOrFqdn"] != server:
                    bad_vm_record = True
            if rpvm_cluster:
                if vm["rpvmCluster"] != rpvm_cluster:
                    bad_vm_record = True
            vm["prodJournalCapGB"] = vm.get("prodJournalCapGB", 3)
            vm["replicaJournalCapyGB"] = vm.get("replicaJournalCapGB", 10)
            vm["rpoSec"] = vm.get("rpoSec", 25)
            if vm.get("failoverNetworkByVnic"):
                vm["failoverNetworkByVnic"] = vm["failoverNetworkByVnic"].split(", ")
        if bad_vm_record:
            del config[index]
    return config


def init_rest_call(verb, uri, creds, payload=None, params=None):
    """Generic function for REST calls"""
    user, password = creds
    headers = {"Content-Type": "application/json"}
    payload = json.dumps(payload)
    verify = False
    timeout = 90
    codes = {200, 201, 202, 204}
    try:
        if verb.lower() == "get":
            response = requests.get(uri, headers=headers,
                                    auth=(user, password), verify=verify,
                                    params=params, timeout=timeout)
        else:
            response = requests.request(verb, uri, headers=headers,
                                        data=payload, auth=(user, password),
                                        verify=verify, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as error:
        print(f"Error Connecting to {uri}: {error}")
    except requests.exceptions.Timeout as error:
        print(f"Connection timed out {urllib3}: {error}")
    except requests.exceptions.RequestException as error:
        if response.status_code == 401:
            return False
        print(f"{response.request.method} {response.url} failed with {error}")
    if response.status_code not in codes:
        return False
    try:
        return response.json()
    except json.decoder.JSONDecodeError:
        if response.status_code == 204:
            return True
        return response.text


def decode_b64_password(b64_password):
    """Decryptes base64 strings"""
    base64_bytes = b64_password.encode('utf-8')
    password_bytes = base64.b64decode(base64_bytes)
    password = password_bytes.decode('utf-8')
    return password


def get_creds(api_endpoint, config):
    """Gets and validates credentials"""
    plugin_servers = {}
    check_uri = f"{api_endpoint}/version"
    for index, vm in enumerate(config):
        if vm.get("credentialsFile"):
            file_handle = open(vm["credentialsFile"], 'r', encoding="utf-8")
            cred_string = file_handle.read().rstrip()
            file_handle.close()
            user, password = cred_string.split(' ')
            vm["vcUser"] = user
            vm["vcPass"] = decode_b64_password(password)
            vm["creds"] = vm["vcUser"], vm["vcPass"]
            if vm["pluginServerIpOrFqdn"] not in plugin_servers:
                uri = f"https://{vm['pluginServerIpOrFqdn']}{check_uri}"
                response = init_rest_call("GET", uri, vm["creds"])
                if response:
                    plugin_servers[vm["pluginServerIpOrFqdn"]] = True
                    vm["credsPass"] = True
                else:
                    plugin_servers[vm["pluginServerIpOrFqdn"]] = False
                    vm["credsPass"] = False
                    print(f"Igoring vm {vm['vmName']}, \
                          login failed to {vm['pluginServerIpOrFqdn']}")
                    del config[index]
            else:
                vm["credsPass"] = plugin_servers[vm["pluginServerIpOrFqdn"]]
                if not vm["credsPass"]:
                    print(f"Igoring vm {vm['vmName']}, \
                          login failed to {vm['pluginServerIpOrFqdn']}")
                    del config[index]
        else:
            vm["creds"] = vm["vcUser"], decode_b64_password(vm["vcPassB64"])
    return config


def sort_by_cluster(config):
    """Sorts VMs by RPVM cluster"""
    vms_by_cluster = {}
    for vm in config:
        cluster = vm["rpvmCluster"]
        if cluster in vms_by_cluster:
            vms_by_cluster[cluster].append(vm)
        else:
            vms_by_cluster[cluster] = [vm]
    return vms_by_cluster


def find_multi_vm_groups(config):
    """Returns a list of groups with multiple VMs"""
    multi_vm_list = []
    for cluster in config:
        group_list = {}
        for vm in config[cluster]:
            if vm["cgName"] in group_list:
                vm_list = [vm]
                vm_list.append(group_list[vm["cgName"]])
                multi_vm_list = {vm["cgName"]: vm_list}
            else:
                group_list = {vm["cgName"]: vm}
        return multi_vm_list


def get_candidates(vm, uri):
    """Gets candidate VMs for replication"""
    suffix = "/vms/protect/candidates"
    uri += suffix
    fields = "id,rpClusterId"
    params = {"vms": "", "name": vm["vmName"],
              "rpClusterName": vm["rpvmCluster"],
              "fields": fields
              }
    response = init_rest_call("GET", uri, vm["creds"], None, params)
    if len(response) == 1:
        # vm["id"] = response[0]["id"]
        # vm["rpClusterId"] = response[0]["rpClusterId"]
        response = response[0]
        default_params = {"vm": response["id"],
                          "rpCluster": response["rpClusterId"]
                          }
        return default_params
    print(f"Detected {len(response)} candidate VMs for VM {vm['vmName']}")
    return False


def compute_defaults(uri, vm, default_params):
    """Gets and applies recommended replication parameters"""
    defaults_uri = f"{uri}/vms/protect/defaults"
    response = init_rest_call(
        "POST", defaults_uri, vm["creds"], default_params
        )
    if not response:
        return False
    response["groupConfiguration"]["productionJournalSizeInMB"] = \
        int(vm["prodJournalCapGB"]) * 1024
    response["groupConfiguration"]["copies"][0]["journalSizeInMB"] = \
        int(vm["replicaJournalCapGB"]) * 1024
    response["groupConfiguration"]["copies"][0]["rpoInSeconds"] = \
        int(vm["rpoSec"])
    if vm.get("cgName"):
        response["groupConfiguration"]["name"] = vm["cgName"]
    else:
        vm["cgName"] = response["groupConfiguration"]["name"]
    return response


def check_cg(api_endpoint, vm):
    """Checks if the provided group exists"""
    suffix = "/groups"
    uri = f"https://{vm['pluginServerIpOrFqdn']}{api_endpoint}{suffix}"
    fields = "id,name,prodRpClusterName"
    params = {"name": vm["cgName"], "fields": fields}
    response = init_rest_call("GET", uri, vm["creds"], None, params)
    if len(response) == 1:
        response = response[0]
    else:
        return False
    if not response:
        return False
    if response.get("prodRpClusterName") != vm["rpvmCluster"]:
        return "Mismatch"
    return True


def protect_vm(uri, vm, protect_params):
    """Protects a specific VM"""
    protect_uri = f"{uri}/vms/protect"
    response = init_rest_call("POST", protect_uri, vm["creds"], protect_params)
    if not response:
        return False
    if "id" not in response:
        return False
    return response["id"]


def monitor_activity(transactions):
    """Monitors an activity by its transaction ID"""
    timeout = 1200
    interval = 10
    start = time.time()
    active_ops = len(transactions)
    if active_ops == 0:
        print("---> VM protection failed")
        return False
    while active_ops > 0:
        if (time.time() - start) > timeout:
            break
        for transaction in transactions:
            vm_name = transaction['vmName']
            trans_id = transaction["id"]
            creds = transaction["creds"]
            uri = f"{transaction["uri"]}/transactions/{transaction["id"]}"
            response = init_rest_call("GET", uri, creds)
            try:
                if "status" in response:
                    transaction["status"] = response["status"]
                    trans_status = transaction["status"]
                    print(f"---> Protection of VM: {vm_name},", end=" ")
                    print(f"Transaction: {trans_id},", end=" ")
                    print(f"Status: {trans_status}")
                else:
                    raise KeyError
            except (TypeError, KeyError):
                transaction["status"] = "ERROR"
                print(f"---> Cannot monitor VM: {vm_name}", end=" ")
                print(f"Transaction: {trans_id}")
            if transaction["status"] != "RUNNING":
                active_ops -= 1
                continue
        print()
        time.sleep(interval)
    return True


def obtain_replication_id_by_vm_id(uri, creds, vm_id):
    "Determines the VM replication ID by its ID"
    uri = f"{uri}/vms/{vm_id}"
    fields = "id,vmReplicationId"
    params = {"role": "PRODUCTION", "fields": fields}
    response = init_rest_call("GET", uri, creds, None, params)
    if response:
        if response.get("vmReplicationId"):
            return response["vmReplicationId"]
    return False


def get_replica_vm_id(uri, creds, vm_rep_id):
    "Gets the replica VM ID based on prod VM ID"
    uri = f"{uri}/vms"
    fields = "id"
    params = {"role": "REPLICA",
              "vmReplicationId": vm_rep_id,
              "fields": fields
              }
    response = init_rest_call("GET", uri, creds, None, params)
    if response:
        if len(response) == 1:
            return response[0]["id"]
    return False


def get_failover_networks(uri, vm_id, creds, network_type=None):
    "Gets failover and available networks"
    if network_type == "avail":
        network_type = "available-"
    else:
        network_type = ""
    uri = f"{uri}/vms/{vm_id}/{network_type}failover-networks"
    response = init_rest_call("GET", uri, creds)
    return response


def get_failover_network_info(network_name, avail_networks):
    "Gets network info based on available networks info"
    counter = 0
    for avail_network in avail_networks:
        if network_name == avail_network["name"]:
            counter += 1
            network_info = avail_network
    if counter > 1:
        return False
    return network_info


def check_failover_networks(uri, vm):
    "Validates and builds failover network configuration"
    avail_networks = get_failover_networks(uri, vm["repVmId"], vm["creds"], "avail")
    failover_networks = get_failover_networks(uri, vm["repVmId"], vm["creds"])
    failover_net_count = len(failover_networks)
    if failover_net_count != len(vm["failoverNetworkByVnic"]):
        print("---> Specified failover networks for VM:", end=" ")
        print(f"{vm["vmName"]} mismatched")
        return False
    for failover_network in failover_networks:
        network_name = failover_network["vcNetwork"]["name"]
        index = failover_network["adapterIndex"] - 1
        config_network = vm["failoverNetworkByVnic"][index]
        if network_name != config_network:
            network_info = get_failover_network_info(config_network, avail_networks)
            if network_info:
                failover_network["vcNetwork"] = network_info
            else:
                print("---> Could not get available networks for VM:", end=" ")
                print(vm["vmName"])
                return False
        else:
            failover_net_count -= 1
    if failover_net_count == 0:
        print("---> Failover networks config is not required for VM:",  end=" ")
        print(vm["vmName"])
        return False
    return failover_networks


def configure_failover_networks(uri, vm, failover_networks):
    "Configures failover network on a per VM basis"
    uri = f"{uri}/vms/{vm["repVmId"]}/failover-networks"
    response = init_rest_call("PATCH", uri, vm["creds"], failover_networks)
    if response:
        return True
    return False


def main():
    api_endpoint = "/api/v1"
    args = get_args()
    config_file, rpvm_cluster = args.config_file, args.rpvm_cluster
    server, no_monitor = args.server, args.no_monitor
    config = read_config(config_file, rpvm_cluster, server)
    config = get_creds(api_endpoint, config)
    transactions = []
    for vm in config:
        uri = f"https://{vm['pluginServerIpOrFqdn']}{api_endpoint}"
        print(f"-> Protecting VM {vm["vmName"]}")
        default_params = get_candidates(vm, uri)
        if default_params:
            vm["valid"] = True
            vm["id"] = default_params["vm"]
            protect_params = compute_defaults(uri, vm, default_params)
            transaction_id = protect_vm(uri, vm, protect_params)
            if transaction_id:
                print(f"---> Protection of VM {vm["vmName"]} initiated")
                transactions.append({"id": transaction_id,
                                     "vmName": vm["vmName"],
                                     "uri": uri,
                                     "creds": vm["creds"]
                                     })
                vm["protected"] = True
    if not no_monitor:
        print("-> VM protection initiated, monitoring")
        monitor_activity(transactions)
    else:
        print("-> VM protection initiated")
    time.sleep(10)
    print("-> Configuring failover networks")
    for vm in config:
        if not vm.get("protected"):
            print("---> Skipping failover network config for VM:", end=" ")
            print(vm["vmName"])
            continue
        if vm.get("failoverNetworkByVnic"):
            vm_rep_id = obtain_replication_id_by_vm_id(uri, vm["creds"], vm["id"])
            uri = f"https://{vm['pluginServerIpOrFqdn']}{api_endpoint}"
            if vm_rep_id:
                vm["repVmId"] = get_replica_vm_id(uri, vm["creds"], vm_rep_id)
                if not vm["repVmId"]:
                    print("---> Skipping failover network config for VM:", end=" ")
                    print(vm["vmName"])
                    continue
            failover_networks = check_failover_networks(uri, vm)
            if failover_networks:
                if configure_failover_networks(uri, vm, failover_networks):
                    print("---> Failover network config is successful for VM:", end=" ")
                    print(vm["vmName"])
                else:
                    print("---> Could not configure Failover networks for VM:", end=" ")
                    print(vm["vmName"])
        else:
            print("---> Skipping failover network config for VM:", end=" ")
            print(vm["vmName"])


if __name__ == "__main__":
    main()

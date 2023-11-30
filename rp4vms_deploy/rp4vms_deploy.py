#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
import time
import requests
import urllib3

# The purpose of this script is to automate RP4VMs deployment
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - September 2022
# Version 2 - November 2022
# Version 3 - January 2023
# Version 4 - February 2023
# Version 5 - October 2023
# Version 6 - November 2023
# Version 7 - December 2023

# Copyright [2023] [Idan Kentor]

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
    # Gets command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to automate RP4VMs deployment')
    parser.add_argument('-configfile', '--config-file', required=True, dest='configfile',
                        action='store', help='Full path to the JSON config file')
    parser.add_argument('-pluginserver', '--config-plugin-server', required=False, action='store_false',
                        dest='pluginserver', default=True, help='Optionally prevents Plugin Server configuration')
    parser.add_argument('-connect', '--connect-another-cluster', required=False, action='store_false',
                        dest='connect', default=True, help='Optionally prevents connection to a different cluster')
    args = parser.parse_args()
    return args

def read_config(configfile):
    # Reads config file, validate params and assigns to config dictionary
    with open(configfile, 'r') as fileHandle:
        try:
            config = json.load(fileHandle)
        except json.decoder.JSONDecodeError as error:
            print("\033[91m\033[1m->Cannot parse JSON config file:\033[0m", {error})
            sys.exit(1)
    fileHandle.close()
    for key in list(config.keys()):
      if key.startswith('_comment'):
            config.pop(key)
    config["vRPACount"] = config.get("vRPACount", 2)
    if 1 > config["vRPACount"] > 8 :
        print("\033[91m\033[1m->Illegal vRPA count - a vRPA cluster must have at least one vRPA and up to 8 vRPAs\033[0m")
        sys.exit(1)
    config["vRPANames"] = config.get("vRPANames")
    if not config["vRPANames"] or (len(config["vRPANames"]) != config["vRPACount"]):
        config["vRPANames"] = []
        for counter in range(config["vRPACount"]):
            config["vRPANames"].append('{}_vRPA{}'.format(config["vRPAClusterName"], counter + 1))
    if not config.get("pluginServerName"):
        config["pluginServerName"] = '{}_Plugin-Server'.format(config["vRPAClusterName"])
    if all(key in config for key in ("vRPAClusterIp", "vRPAMgmtIPs", "mgmtSubnet", "mgmtNetwork", "mgmtGateway")):
        if not config.get("pluginServerSubnet"):
            config["pluginServerSubnet"] = config["mgmtSubnet"]
        if not config.get("pluginServerGateway"):
            config["pluginServerGateway"] = config["mgmtGateway"]
        if not config.get("pluginServerNetwork"):
            config["pluginServerNetwork"] = config["mgmtNetwork"]
    else:
        print("\033[91m\033[1m->Missing IP configuration parameters\033[0m")
        sys.exit(1)
    if (not config.get("repoDatastore") and not config.get("vRPADatastore")):
        print("\033[91m\033[1m->No Datastore provided, specify DS for repository and/or vRPAs\033[0m")
        sys.exit(1)
    if not config.get("vRPADatastore"):
        config["vRPADatastore"] = config["repoDatastore"]
    if not config.get("repoDatastore"):
        config["repoDatastore"] = config["vRPADatastore"]
    if not config.get("mgmtMTU"):
        config["mgmtMTU"] = 1500
    if not config.get("wanMTU"):
        config["wanMTU"] = 1500
    if not config.get("dataMTU"):
        config["dataMTU"] = 1500
    if len(config["vRPAMgmtIPs"]) != config["vRPACount"]:
        print("\033[91m\033[1m->Incorrect number of vRPA management IPs\033[0m")
        sys.exit(1)
    if not config.get("vcPort"):
        config["vcPort"] = 443
    if not config.get("vRPAHWProfile"):
        config["vRPAHWProfile"] = "Min"
    else:
        hwProfile = {'Bronze': "Min", 'Silver': "Med", 'Gold': "Max"}
        config["vRPAHWProfile"] = hwProfile[config["vRPAHWProfile"]]
    if config.get("NTPServers") and config.get("DNSServers"):
        config["NTPServers"] = config["NTPServers"][0].split(", ")
        config["DNSServers"] = config["DNSServers"][0].split(", ")
    else:
        print("\033[91m\033[1m->Missing DNS and/or NTP settings\033[0m")
        sys.exit(1)
    if not config.get("partnerClusterAdminPwd"):
        config["partnerClusterAdminPwd"] = config["vRPAAdminPwd"]
    if all(key in config for key in ("additionalGwIP", "additionalGwTgtNetwork", "additionalGwTgtNetmask")):
        config["additionalGw"] = True
    else:
        config["additionalGw"] = False
    return config

def compute_nic_role(config):
    # Computes the NIC role data structures
    config["nicRole"] = []
    if config["networkTopology"] == "DATA_IS_SEPARATED":
        if not config["dataNetwork"]:
            print("\033[91m\033[1m->Data Network Port Group must be specified\033[0m")
            sys.exit(1)
        elif len(config["vRPADataIPs"]) != config["vRPACount"]:
            print("\033[91m\033[1m->Incorrect number of vRPA data IPs\033[0m")
            sys.exit(1)
        config["nicRoleMtu"] = {"WAN_LAN": config["mgmtMTU"], "DATA": config["dataMTU"]}
        config["nicRoleVlan"] = {"WAN_LAN": config["mgmtNetwork"], "DATA": config["dataNetwork"]}
        for counter in range(config["vRPACount"]):
            NicRoleTag = {}
            ipInfoList = {}
            dataIpInfoList = {}
            ipInfoList["ipVersion"] = "IP_V_4"
            ipInfoList["fromDHCP"] = False
            ipInfoList["ipAddress"] = {"ip": config["vRPAMgmtIPs"][counter], "netmask": config["mgmtSubnet"]}
            NicRoleTag["WAN_LAN"] = {"ipInfoList": [ipInfoList]}
            dataIpInfoList["ipVersion"] = "IP_V_4"
            dataIpInfoList["fromDHCP"] = False
            dataIpInfoList["ipAddress"] = {"ip": config["vRPADataIPs"][counter], "netmask": config["dataSubnet"]}
            NicRoleTag["DATA"] = {"ipInfoList": [dataIpInfoList]}
            config["nicRole"].append(NicRoleTag)
    elif config["networkTopology"] == "WAN_IS_SEPARATED":
        if not config["wanNetwork"]:
            print("\033[91m\033[1m->WAN Network Port Group must be specified\033[0m")
            sys.exit(1)
        elif len(config["vRPAWANIPs"]) != config["vRPACount"]:
            print("\033[91m\033[1m->incorrect number of vRPA WAN IPs\033[0m")
            sys.exit(1)
        config["nicRoleMtu"] = {"LAN_DATA": int(config["mgmtMTU"]), "WAN": int(config["wanMTU"])}
        config["nicRoleVlan"] = {"LAN_DATA": config["mgmtNetwork"], "WAN": config["wanNetwork"]}
        for counter in range(config["vRPACount"]):
            NicRoleTag = {}
            ipInfoList = {}
            wanIpInfoList = {}
            ipInfoList["ipVersion"] = "IP_V_4"
            ipInfoList["fromDHCP"] = False
            ipInfoList["ipAddress"] = {"ip": config["vRPAMgmtIPs"][counter], "netmask": config["mgmtSubnet"]}
            NicRoleTag["LAN_DATA"] = {"ipInfoList": [ipInfoList]}
            wanIpInfoList["ipVersion"] = "IP_V_4"
            wanIpInfoList["fromDHCP"] = False
            wanIpInfoList["ipAddress"] = {"ip": config["vRPAWANIPs"][counter], "netmask": config["wanSubnet"]}
            NicRoleTag["WAN"] = {"ipInfoList": [wanIpInfoList]}
            config["nicRole"].append(NicRoleTag)
    elif config["networkTopology"] == "ALL_ARE_SEPARATED":
        if not config["wanNetwork"] or not config["dataNetwork"]:
            print("\033[91m\033[1m->WAN and Data Network Port Groups must be specified\033[0m")
            sys.exit(1)
        elif config["vRPACount"] != len(config["vRPAWANIPs"]) or config["vRPACount"] != len(config["vRPADataIPs"]):
            print("\033[91m\033[1m->incorrect number of vRPA WAN and/or Data IPs\033[0m")
            sys.exit(1)
        config["nicRoleMtu"] = {"WAN": int(config["wanMTU"]), "LAN": int(config["mgmtMTU"]), "DATA": int(config["dataMTU"])}
        config["nicRoleVlan"] = {"WAN": config["wanNetwork"], "LAN": config["mgmtNetwork"], "DATA": config["dataNetwork"]}
        for counter in range(config["vRPACount"]):
            NicRoleTag = {}
            ipInfoList = {}
            wanIpInfoList = {}
            dataIpInfoList = {}
            ipInfoList["ipVersion"] = "IP_V_4"
            ipInfoList["fromDHCP"] = False
            ipInfoList["ipAddress"] = {"ip": config["vRPAMgmtIPs"][counter], "netmask": config["mgmtSubnet"]}
            NicRoleTag["LAN"] = {"ipInfoList": [ipInfoList]}
            wanIpInfoList["ipVersion"] = "IP_V_4"
            wanIpInfoList["fromDHCP"] = False
            wanIpInfoList["ipAddress"] = {"ip": config["vRPAWANIPs"][counter], "netmask": config["wanSubnet"]}
            NicRoleTag["WAN"] = {"ipInfoList": [wanIpInfoList]}
            dataIpInfoList["ipVersion"] = "IP_V_4"
            dataIpInfoList["fromDHCP"] = False
            dataIpInfoList["ipAddress"] = {"ip": config["vRPADataIPs"][counter], "netmask": config["dataSubnet"]}
            NicRoleTag["DATA"] = {"ipInfoList": [dataIpInfoList]}
            config["nicRole"].append(NicRoleTag)
    elif config["networkTopology"] == "ALL_IN_ONE":
        config["nicRoleVlan"] = {"WAN_LAN_DATA": config["mgmtNetwork"]}
        config["nicRoleMtu"] = {"WAN_LAN_DATA": int(config["mgmtMTU"])}
        for counter in range(config["vRPACount"]):
            NicRoleTag = {}
            ipInfoList = config["vRPAInfo"][counter]["ipInfo"]
            NicRoleTag["WAN_LAN_DATA"] = {"ipInfoList": [ipInfoList]}
            config["nicRole"].append(NicRoleTag)
    else:
        print("\033[91m\033[1m->Illegal network topology\033[0m")
        sys.exit(1)
    return config

def create_ovftool_command(config):
    # Forms the required ovftool commands
    print()
    ovfexecrpc = '{} --noDestinationSSLVerify --skipManifestCheck --acceptAllEulas --powerOn --name="{}" '.format(config["ovfToolLocation"], config["pluginServerName"])
    ovfexecrpc += '--diskMode=thin --datastore={} --net:"Plugin Server Management Network"="{}" '.format(config["repoDatastore"], config["pluginServerNetwork"])
    ovfexecrpc += '--prop:vami.ip0.brs={} --prop:vami.netmask0.brs="{}" --prop:vami.gateway.brs="{}" '.format(config["pluginServerIP"], config["pluginServerSubnet"], config["pluginServerGateway"])
    ovfexecrpc += '--prop:vami.DNS.brs="{}" --prop:vami.fqdn.brs="{}" --prop:vami.ntp_servers.brs="{}" --allowExtraConfig '.format(" ".join(config["DNSServers"]), config["pluginServerFQDN"], " ".join(config["NTPServers"]))
    ovfexecrpc += '--extraConfig:RecoverPoint.PluginServer="RPC" "{}" vi://"{}":"{}"@{}/{}/host/{}/'.format(config["pluginServerOVALocation"], config["vcUser"], config["vcPassword"], config["vcIP"], config["datacenter"], config["esxCluster"])
    ovfexecvrpa = []
    for counter in range(config["vRPACount"]):
        ovfexecvrpa.append('{} --noDestinationSSLVerify --skipManifestCheck --acceptAllEulas --powerOn --name="{}" '.format(config["ovfToolLocation"], config["vRPANames"][counter]))
        ovfexecvrpa[counter] += '--diskMode=thin --datastore={} --net:"RecoverPoint Management Network"="{}" '.format(config["repoDatastore"], config["mgmtNetwork"])
        ovfexecvrpa[counter] += '--prop:ip={} --prop:netmask="{}" --prop:gateway="{}" '.format(config["vRPAMgmtIPs"][counter], config["mgmtSubnet"], config["mgmtGateway"])
        ovfexecvrpa[counter] += '--allowExtraConfig --deploymentOption="{}" '.format(config["vRPAHWProfile"])
        ovfexecvrpa[counter] += '"{}" vi://"{}":"{}"@{}/{}/host/{}/'.format(config["vRpaOVALocation"], config["vcUser"], config["vcPassword"], config["vcIP"], config["datacenter"], config["esxCluster"])
    return ovfexecrpc, ovfexecvrpa

def exec_ova_provisioning(ovfexec):
    # Executes ovftool commands
    exitCode = os.system(ovfexec)
    if (exitCode == 0):
        print("\033[92m\033[1m ---> OVA deployment completed successfully\033[0m")
    else:
        print("\033[91m\033[1m ---> OVA deployment failed\033[0m")
        sys.exit(1)

def init_rest_call(callType, uri, token, payload=None, params=None, deploy=None):
    # Generic function for REST calls
    if uri.endswith("/user/sessions"):
        username, password = token.values()
        headers = {'Content-Type': 'application/json'}
    else:
        headers = {'Content-Type': 'application/json', 'X-Auth-Token': token}
    payload = json.dumps(payload)
    code = {200, 202, 204}
    verify = False
    try:
        if callType.lower() == "get":
            response = requests.get(uri, headers=headers, params=params, verify=verify)
        elif callType.lower() == "post":
            response = requests.post(uri, headers=headers, params=params, data=payload, verify=verify)
        elif callType.lower() == "put":
            response = requests.put(uri, headers=headers, params=params, data=payload , verify=verify)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as err:
        if deploy:
            return False
        print('\033[91m\033[1m->Error Connecting to {}: {}\033[0m'.format(uri, err))
        sys.exit(1)
    except requests.exceptions.Timeout as err:
        print('\033[91m\033[1m->Connection timed out {}: {}\033[0m'.format(urllib3, err))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        if deploy and response.status_code == 401:
            return False
        print("\033[91m\033[1m->The call {} {} failed with exception:{}\033[39m".format(response.request.method, response.url, err))
    if (response.status_code not in code):
        raise Exception('\033[91m\033[1m->Failed to query {}, code: {}, body: {}\033[39m'.format(uri, response.status_code, response.text))
    if not response.content:
        return True
    else:
        return response.json()

def monitor_deploy_activity(transaction, uri, token, deploy=None, adminPwd=None, connect=None):
    # Generic function to monitor deployment API calls
    username = "admin"
    monitorUri = "{}/transactions/{}".format(uri, transaction)
    timeout = 600
    interval = 5
    start = time.time()
    requiresAuth = True
    while True:
        if (time.time() - start) > timeout:
            break
        response = init_rest_call("GET", monitorUri, token, None, None, True)
        if deploy:
            if not response:
                if not requiresAuth:
                    response = init_rest_call("GET", monitorUri, token, None, None, True)
                else:
                    login = {"username": username, "password": adminPwd}
                    loginUri = '{}/user/sessions'.format(uri)
                    token = init_rest_call("POST", loginUri, login, login)
                    token = token["token"]
                    try:
                        response = init_rest_call("GET", monitorUri, token, None, None, True)
                    except:
                        time.sleep(30)
                        response = init_rest_call("GET", monitorUri, token, None, None, True)
                    requiresAuth = True
        if response['state'] == 'SUCCESS':
            if deploy:
                return True
            if connect:
                return response
            monitorUri += "/result"
            response = init_rest_call("GET", monitorUri, token)
            return response
        elif response['state'] == 'ERROR':
            print("\033[91m\033[1m->Action failed:\033[39m", json.dumps(response))
            break
        print('---> Transaction {} {} {}%'.format(transaction, response['state'], response['progress']))
        time.sleep(interval)
    return False

def handle_array_certificate(arrayIP, uri, token, arrayPort):
    # Handles certificates approval via REST
    payload = {"ip": arrayIP, "port": arrayPort}
    certUri = '{}/arrays/certificate'.format(uri)
    cert = init_rest_call("POST", certUri, token, payload)
    payload = {"alias": cert["alias"], "certificate": cert["asBase64"]["certificate"]}
    certUri = '{}/operations/trusted_certificate'.format(uri)
    init_rest_call("POST", certUri, token, payload)
    return payload

def validate_virtual_env(config, uri, token):
    # Executes pre-deployment validation checks
    payload = handle_array_certificate(config["vcIP"], uri, token, config["vcPort"])
    vcUri = '{}/current_rpa/virtual_center'.format(uri)
    vcCreds = {
            "ip": config["vcIP"], "port": config["vcPort"],
            "user": config["vcUser"],
            "password": config["vcPassword"], "certificate": payload["certificate"],
            "type": "VIRTUAL_CENTER"
            }
    init_rest_call("POST", vcUri, token, vcCreds)
    vcUri = '{}/arrays/virtual_center/entities/validations'.format(uri)
    payload = {"vcCredentials": vcCreds, "entities":[]}
    transaction = init_rest_call("POST", vcUri, token, payload)
    result = monitor_deploy_activity(transaction["id"], uri, token)
    if result[0]["severity"] == "SUCCESS":
        print("\033[92m\033[1m---> Pre-installation validation passed successfully\033[0m")
    elif result[0]["severity"] == "WARNING":
        print("\033[93m\033[1m---> Warnings detected in pre-installation validation\033[0m")
        print("--->", result[0]["message"])
    else:
        print("\033[91m\033[1m---> Errors detected in pre-installation validation\033[0m")
        print("--->", result[0]["message"])
        sys.exit(1)
    return vcCreds

def check_ntp_dns(config, uri, token, vcCreds):
    # Checks NTP and DNS server input
    if config["NTPServers"] and config["DNSServers"]:
        return config
    else:
        recNetUri = "{}/operations/recommended_network_configuration".format(uri)
        recNet = init_rest_call("POST", recNetUri, token, vcCreds)
        if not config["NTPServers"]:
            config["NTPServers"] = recNet["ntpServersIps"]
        if not config["DNSServers"]:
            config["DNSServers"] = recNet["dnsServersIps"]
        return config

def find_timezone(config, uri, token):
    # Determines the time zone
    if not config["timezone"]:
        config["timezone"] = str(datetime.datetime.now().astimezone().tzinfo).split(' ')[0]
    if config["timezone"].lower() == "eastern" or config["timezone"].lower() == "et":
        config["timezone"] = "US/Eastern"
    elif config["timezone"].lower() == "central" or config["timezone"].lower() == "ct":
        config["timezone"] = "US/Central"
    elif config["timezone"].lower() == "pacific" or config["timezone"].lower() == "pt":
        config["timezone"] = "US/Pacific"
    elif config["timezone"].lower() == "etc" or config["timezone"].lower() == "utc":
        config["timezone"] = "Etc/UTC"
    tzUri = '{}/timezones'.format(uri)
    timezones = init_rest_call("GET", tzUri, token)
    for tz in timezones:
        if config["timezone"] in tz:
            config["timezone"] = tz.split(' ')[-1]
    print("-> Timezone detected: {}".format(config["timezone"]))
    return config

def config_vrpas(config, uri, token, vcCreds):
    # Searches for available vRPAs using REST
    availRPAsUri = '{}/arrays/virtual_center/entities/available_rpas/deploy'.format(uri)
    vcCreds = {"vcCredentials": vcCreds}
    vcCreds["includeCurrentClusterRPAs"] = True
    transaction = init_rest_call("POST", availRPAsUri, token, vcCreds)
    print("-> Searching for available vRPAs")
    availRPAs = monitor_deploy_activity(transaction["id"], uri, token)
    config["vRPAUuid"] = []
    vrpaMatch = 0
    if len(availRPAs["availableVrpas"]) >= config["vRPACount"]:
        for counter, vrpa in enumerate(availRPAs["availableVrpas"]):
            if vrpa["vmName"] in config["vRPANames"]:
                if vrpa["ipInfo"]["ipAddress"]["ip"] in config["vRPAMgmtIPs"]:
                    vrpaMatch += 1
                    vrpaPos = config["vRPANames"].index(vrpa["vmName"])
                    vrpaInfoTemp = availRPAs["availableVrpas"][vrpaPos]
                    availRPAs["availableVrpas"][vrpaPos] = vrpa
                    availRPAs["availableVrpas"][counter] = vrpaInfoTemp
                    config["vRPAUuid"].append(availRPAs["availableVrpas"][vrpaPos]["vmUuid"])
        if vrpaMatch != config["vRPACount"]:
            print("\033[91m\033[1m---> Could not detect sufficient number of available vRPAs\033[0m")
            sys.exit(1)
    else:
        print("\031[91m\033[1m---> Could not detect sufficient number of available vRPAs\033[0m")
        sys.exit(1)
    config["vRPAInfo"] = availRPAs["availableVrpas"]
    return config

def config_repo(config, uri, token, vcCreds):
    # Determines datastore for the repository volume
    availResPoolUri = '{}/arrays/VIRTUAL_CENTER/available_resource_pools'.format(uri)
    payload = {"arrayCredentials": vcCreds, "rpasIps": config["vRPAMgmtIPs"]}
    payload["splitterTypesToInstall"] = config["splitterType"]
    availRepoDs = init_rest_call("POST", availResPoolUri, token, payload)
    for ds in availRepoDs["resourcePools"]:
        if ds["name"] == config["repoDatastore"]:
            print("-> DS for Repository Volume detected")
            config["repoUid"] = ds["uid"]
            return config
    print("\031[94m\033[1m-> Repository DS could not be found\033[0m")
    sys.exit(1)

def match_network_pgs(networkType, networkPg, commonPg):
    # Matches specified network port groups to observed ones 
    if networkPg in commonPg:
        return networkPg
    else:
        counter = 0
        for portGroup in commonPg:
            if networkPg in portGroup:
                counter += 1
                matchedPortGroup = portGroup
        if counter == 1:
            return matchedPortGroup
        elif counter > 1:
            print("\031[94m\033[1m-> Multiple {} networks detected, use exact name\033[0m".format(networkType))
            print("\031[94m\033[1m-> Use the following convention: 'PG (vDS)'\033[0m")
            sys.exit(1)
        else:
            return False

def validate_network_pgs(config, uri, token, vcCreds):
    # Validates network port groups
    commonPgUri = '{}/operations/common_vlan_names'.format(uri)
    payload = {"vmUids": config["vRPAUuid"], "arrayCreds": vcCreds}
    commonPg = init_rest_call("POST", commonPgUri, token, payload)
    matchedPortGroup = match_network_pgs("MGMT", config["mgmtNetwork"], commonPg)
    if matchedPortGroup:
        config["mgmtNetwork"] = matchedPortGroup
        print("-> Mgmt Network detected")
    else:
        print("\031[94m\033[1m-> Mgmt Network could not be found\033[0m")
        sys.exit(1)
    if config["networkTopology"] == "DATA_IS_SEPARATED":
        matchedPortGroup = match_network_pgs("Data", config["dataNetwork"], commonPg)
        if matchedPortGroup:
            config["dataNetwork"] = matchedPortGroup
            print("-> Data Network detected")
        else:
            print("\031[94m\033[1m-> Data Network could not be found\033[0m")
            sys.exit(1)
    elif config["networkTopology"] == "WAN_IS_SEPARATED":
        matchedPortGroup = match_network_pgs("WAN", config["wanNetwork"], commonPg)
        if matchedPortGroup:
            config["wanNetwork"] = matchedPortGroup
            print("-> WAN Network detected")
        else:
            print("\031[94m\033[1m-> WAN Network could not be found\033[0m")
            sys.exit(1)
    elif config["networkTopology"] == "ALL_ARE_SEPARATED":
        matchedPortGroup = match_network_pgs("WAN", config["wanNetwork"], commonPg)
        if matchedPortGroup:
            config["wanNetwork"] = matchedPortGroup
        else:
            print("\031[94m\033[1m-> WAN Network could not be found\033[0m")
            sys.exit(1)
        matchedPortGroup = match_network_pgs("Data", config["dataNetwork"], commonPg)
        if matchedPortGroup:
            config["dataNetwork"] = matchedPortGroup
        else:
            print("\031[94m\033[1m-> Data Network could not be found\033[0m")
            sys.exit(1)
        print("-> WAN and Data Networks detected")
    return config

def build_deploy_config(config, vcCreds):
    # Build cluster deployment data structure
    deployConfig = {}
    basicClusterInfo = {}
    dgwDetails = {"gatewayIP": config["mgmtGateway"], "targetNetmask": "0.0.0.0", "targetNetwork": "default"}
    basicClusterInfo["defaultGatewayDetails"] = [dgwDetails]
    basicClusterInfo["clusterManagementIPs"] = config["vRPAClusterIp"].split()
    if config["DNSServers"]:
        if len(config["DNSServers"]) == 1:
            basicClusterInfo["primaryDns"] = config["DNSServers"][0]
        else:
            basicClusterInfo["primaryDns"], basicClusterInfo["secondaryDns"] = config["DNSServers"][0:2]
    if config["NTPServers"]:
        basicClusterInfo["ntpServers"] = config["NTPServers"]
    basicClusterInfo["timezone"] = config["timezone"]
    basicClusterInfo["clusterName"] = config["vRPAClusterName"]
    advancedParameters = {}
    advancedParameters["additionalWWNs"] = 1
    advancedParameters["numberOfIqns"] = 1
    advancedParameters["mtuInfo"] = {}
    advancedParameters["mtuInfo"]["nicRoleToMtu"] = config["nicRoleMtu"]
    basicClusterInfo["advancedParameters"] = advancedParameters
    basicClusterInfo["dnsDomain"] = None
    basicClusterInfo["productType"] = "RP4VM"
    deployConfig["basicClusterInfo"] = basicClusterInfo
    infoAboutRPAs = []
    for counter in range(len(config["vRPAMgmtIPs"])):
        infoAboutRPAs.append({"rpUser": "admin"})
        infoAboutRPAs[counter]["rpPassword"] = "admin"
        infoAboutRPAs[counter]["networkTopology"] = config["networkTopology"]
        vrpaUuid= {"id": config["vRPAInfo"][counter]["vmUuid"]}
        infoAboutRPAs[counter]["vmUuid"] = {}
        infoAboutRPAs[counter]["vmUuid"] = vrpaUuid["id"]
        infoAboutRPAs[counter]["iscsiPortNumber"] = 3260
        infoAboutRPAs[counter]["newIPs"] = {"nicRoleToInfo": config["nicRole"][counter]}
        infoAboutRPAs[counter]["vlansInfo"] = {"nicRoleToVlanName": config["nicRoleVlan"]}
    deployConfig["infoAboutRPAs"] = infoAboutRPAs
    deployConfig["vcCredentials"] = vcCreds
    deployConfig["resourcePoolId"] = config["repoDatastore"]
    deployConfig["securityLevel"] = config["wanEncryption"]
    deployConfig["splitterTypesToInstall"] =  config["splitterType"]
    deployConfig["splitterCommunicationMode"] = "IP"
    deployConfig["securityInfo"] = {}
    deployConfig["securityInfo"]["localUserCredentialsList"] = [{"username": "ADMIN", "password": config["vRPAAdminPwd"]}]
    return deployConfig

def bootstrap_cluster(config, uri, token, deployConfig):
    # Executes the cluster deployment process
    bootstrapUri ='{}/clusters'.format(uri)
    queryParams = {"force": "true", "deploy": "true", "retry": "false", "performDeployValidations": "false"}
    transaction = init_rest_call("POST", bootstrapUri, token, deployConfig, queryParams)
    result = monitor_deploy_activity(transaction["id"], uri, token, True, config["vRPAAdminPwd"])
    if result:
        print("\033[92m\033[1m-> Cluster deployed successfully\033[0m")
    else:
        print("\033[91m\033[1m-> Cluster deployment failed\033[0m")
        print(result)
        sys.exit(1)
    return True

def configure_plugin_server(config, uri, token):
    # Configures the plugin server on the created RP4VMs cluster
    print("-> Configuring Plugin Server")
    pluginServerPort = 443
    handle_array_certificate(config["pluginServerIP"], uri, token, pluginServerPort)
    registerPluginUri = '{}/clusters/current/register_cluster_vc_to_rp_center'.format(uri)
    payload = {"rpCenterIp": config["pluginServerIP"]}
    init_rest_call("POST", registerPluginUri, token, payload)
    print("\033[92m\033[1m-> Plugin Server configured successfully\033[0m")
    return True

def check_connectivity(ipAddress):
    # Generic call to check connectivity to a given IP address
    ack = False
    timeout = 600
    interval = 5
    start = time.time()
    if platform.system().lower()=="windows":
        pingCmd = "ping {} -n 3".format(ipAddress)
    else:
        pingCmd = "ping {} -c 3".format(ipAddress)
    while True:
        if (time.time() - start) > timeout:
            ack = False
            break
        result=subprocess.run(pingCmd, shell=True, stdout=subprocess.PIPE)
        if result.returncode == 0:
            ack = True
            break
        time.sleep(interval)
    return ack

def add_gateway(config, uri, token):
    # Configures additional gateway for current cluster
    print("-> Configuring additional gateway")
    gwUri = '{}/clusters/current/gateways'.format(uri)
    queryParams = {"timeout": "30", "isForce": "true"}
    payload = {
        "defaultGateways":[config["mgmtGateway"]],
        "additionalGateways":[{
            "targetNetwork": config["additionalGwTgtNetwork"],
            "gatewayIP": config["additionalGatewayIP"],
            "targetNetmask": config["additionalGwTgtNetmask"]}]
            }
    transaction = init_rest_call("PUT", gwUri, token, payload, queryParams)
    result = monitor_deploy_activity(transaction["id"], uri, token)
    if result["state"] == "SUCCESS":
        print("\033[92m\033[1m---> Additional gateway configured successfully\033[0m")
    else:
        print("\033[91m\033[1m---> Could not configure additional gateway\033[0m")
        sys.exit(1)

def connect_clusters(config, uri, token):
    # Executes the connect cluster process including pre-checks
    print("-> Running connectivity checks to peer cluster")
    validateUri = '{}/clusters/current/links/ip/validations'.format(uri)
    if config["vRPAWANIPs"]:
        wanIP = config["vRPAWANIPs"][0]
    else:
        wanIP = config["vRPAMgmtIPs"][0]
    payload = {"wanIPOfNewCluster": wanIP, "password": config["partnerClusterAdminPwd"]}
    transaction = init_rest_call("POST", validateUri, token, payload)
    result = monitor_deploy_activity(transaction["id"], uri, token)
    if result[1]["severity"] == "SUCCESS":
        print("\033[92m\033[1m---> Connectivity checks to peer cluster completed successfully\033[0m")
    else:
        print("\033[91m\033[1m---> Connectivity issues to peer cluster detected\033[0m")
        sys.exit(1)
    print("-> Connecting clusters")
    connectUri = '{}/clusters/current/links/ip'.format(uri)
    transaction = init_rest_call("POST", connectUri, token, payload)
    result = monitor_deploy_activity(transaction["id"], uri, token, None, None, True)
    if result["state"] == "SUCCESS":
        print("\033[92m\033[1m---> Clusters Connect completed successfully\033[0m")
    elif result["state"] == "WARNING":
        print("\033[93m\033[1m---> Warnings detected in the Cluster connection Process\033[39m")
        print("--->", result["message"])
    else:
        print("\033[91m\033[1m---> Errors detected in the cluster connection process\033[0m")
        print("--->", result[0]["message"])
        sys.exit(1)

def main():
    # Args assignment
    args = get_args()
    configfile = args.configfile
    config = read_config(configfile)
    configPluginServer = args.pluginserver
    connectClustersCheck = args.connect

     # Const definition
    apiEndpoint = "/deployer/rest/5_2"
    username, password = "admin", "admin"
    config["wanEncryption"] = "ENCRYPT"
    clusterWaitTimeout = 120
    defaultSplitterType = "VSCSI"

    # Detect splitter type. IOF is valid for RPVM 6.0 and later
    if not config.get("splitterType"):
        config["splitterType"] = [defaultSplitterType]
    elif config["splitterType"] in ("VSCSI", "IOF"):
        config["splitterType"] = [config["splitterType"]]
    else:
        print('\033[91m\033[1m-> The wrong splitterType was provided - must be either VSCSI or IOF\033[0m')
        sys.exit(1)
   
    # Creates the ovftool commands for Plugin Server and vRPAs
    ovfexecrpc, ovfexecvrpa = create_ovftool_command(config)
    # Executes Plugin Server OVA Deployment (configuration enabled by default)
    if configPluginServer:
        print("-> Provisioning Plugin Server from OVA")
        if not config["pluginServerIP"] or not config["pluginServerFQDN"]:
            print('\033[91m\033[1m-> Missing Plugin Server details\033[0m')
            sys.exit(1)
        exec_ova_provisioning(ovfexecrpc)
    # Executes vRPA OVA Deployment
    for counter in range(config["vRPACount"]):
        print('-> Provisioning vRPA{} from OVA\033[0m'.format(counter+1))
        exec_ova_provisioning(ovfexecvrpa[counter])

    # Checking connectivity to vRPA Mgmt IPs
    print('-> Checking connectivity to vRPAs')
    for vRPAMgmtIP in config["vRPAMgmtIPs"]:
        if not check_connectivity(vRPAMgmtIP):
            print("\033[91m\033[1m ---> vRPA MGMT IP {} is unreachable".format(vRPAMgmtIP))
        else:
            print("---> vRPA Mgmt IP {} is reachable".format(vRPAMgmtIP))
    print('\033[92m\033[1m---> All vRPAs are reachable\033[0m')

    # Logs into the RP4VMs Deployment API
    uri = "https://{}{}".format(config["vRPAMgmtIPs"][0], apiEndpoint)
    loginPayload = {"username": username, "password": password}
    loginUri = '{}/user/sessions'.format(uri)
    token = init_rest_call("POST", loginUri, loginPayload, loginPayload)
    token = token["token"]

    # Runs pre-deployment validations and gets environment settings
    print("-> Running deployment pre-validation checks")
    vcCreds = validate_virtual_env(config, uri, token)
    config = check_ntp_dns(config, uri, token, vcCreds)
    config = find_timezone(config, uri, token)
    config = config_vrpas(config, uri, token, vcCreds)
    config = compute_nic_role(config)
    config = config_repo(config, uri, token, vcCreds)
    config = validate_network_pgs(config, uri, token, vcCreds)

    # Builds Deployment data structure
    print("-> Building deployment configuration")
    deployConfig = build_deploy_config(config, vcCreds)

    # Executes cluster deployment
    print("-> Deploying RP4VMs cluster")
    bootstrap_cluster(config, uri, token, deployConfig)

    # Checks connectivity to cluster mgmt IP
    print('-> Checking connectivity to cluster Mgmt IP')
    if not check_connectivity(config["vRPAClusterIp"]):
        print("\033[91m\033[1m---> vRPA Cluster IP is unreachable\033[0m")
        sys.exit(1)
    # Additional delay for the deployment API server
    time.sleep(clusterWaitTimeout)
    print('\033[92m\033[1m---> vRPA Cluster is reachable\033[0m')

    # Configures Plugin Server (by default, plugin server configuration is enabled)
    if configPluginServer:
        print('-> Checking connectivity to Plugin Server')
        if not check_connectivity(config["pluginServerIP"]):
            print("\033[91m\033[1m---> Plugin Server is unreachable\033[0m")
            sys.exit(1)
        print('\033[92m\033[1m---> Plugin Server is reachable\033[0m')
        # Logins to the API using the new RP4VMs admin pwd
        uri = "https://{}{}".format(config["vRPAClusterIp"], apiEndpoint)
        loginPayload = {"username": username, "password": config["vRPAAdminPwd"]}
        loginUri = '{}/user/sessions'.format(uri)
        token = init_rest_call("POST", loginUri, loginPayload, loginPayload)
        token = token["token"]
        configure_plugin_server(config, uri, token)

    # Connects the newly deployed RP4VMs cluster to a different cluster (option enabled by default)
    if connectClustersCheck:
        # Makes sure that the IP of the other cluster has been specified in the config file
        try:
            if not config["partnerClusterVRpaClusterIP"]:
                print("\033[91m\033[1m-> Missing peer cluster IP\033[0m")
                sys.exit(1)
        except KeyError:
            print("\033[91m\033[1m-> Missing peer cluster IP\033[0m")
            sys.exit(1)
        # Checks connectivity to the peer cluster mgmt IP
        if not check_connectivity(config["partnerClusterVRpaClusterIP"]):
            print("\033[91m\033[1m---> Peer cluster IP is unreachable\033[0m")
            sys.exit(1)
        # Configures Additional gateway on newly deployed cluster
        if config["additionalGw"]:
            add_gateway(config, uri, token)
        # Logs into the peer cluster deployment API and connects the clusters
        existingClusterUri = "https://{}{}".format(config["partnerClusterVRpaClusterIP"], apiEndpoint)
        loginPayload = {"username": username, "password": config["partnerClusterAdminPwd"]}
        existingClusterLoginUri = '{}/user/sessions'.format(existingClusterUri)
        token = init_rest_call("POST", existingClusterLoginUri, loginPayload, loginPayload)
        token = token["token"]
        connect_clusters(config, existingClusterUri, token)
        print('\033[92m\033[1m-> All tasks completed successfully\033[0m')

if __name__ == "__main__":
    main()

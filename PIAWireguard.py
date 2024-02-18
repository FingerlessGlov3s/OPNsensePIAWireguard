#!/usr/local/bin/python3

"""
This script automates the process of getting Wireguard setup on OPNsense to connect to PIA's NextGen Wireguard servers.
It will create Wireguard Instance(local) and Client(peer) on your OPNsense setup.
You will need to assign the new wireguard interface and create a dynamic gateway for it, this can't be automated due to
API retrictions.
Script will check the Wireguard tunnel is functioning by checking handshake before changing over to a different wireguard server
Please run this script every 5-15 minutes via cron.

See github Readme for setup instructions

Created by FingerlessGloves
FingerlessGlov3s on Github


"WireGuard" is a registered trademarks of Jason A. Donenfeld.
"Private Internet Access" is owned by Private Internet Access, Inc. All Rights Reserved
"""

import argparse
import base64
import datetime
import ipaddress
import json
import logging
import os
import re
import requests
import socket
import subprocess
import sys
import time
import urllib3
import secrets

#
# Please see PIAWireguard.json for configuration settings
#


#
# Script Start
#

def validate_json(data):
    required_keys = ["opnsenseURL", "opnsenseKey", "opnsenseSecret", "piaUsername", "piaPassword", "opnsenseWGPrefixName", "instances"]
    for key in required_keys:
        if key not in data:
            raise ValueError(f"Missing required key: {key}")

    # Additional checks for non-blank string properties
    string_properties = ["opnsenseKey", "piaUsername", "piaPassword", "opnsenseWGPrefixName"]
    for prop in string_properties:
        value = data.get(prop, "")
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Property '{prop}' must be a non-blank string")

    # Validate 'instances'
    instances = data.get("instances", {})
    if not isinstance(instances, dict) or not 1 <= len(instances) <= 10:
        raise ValueError("Invalid 'instances' structure")

    opnsenseWGPorts = set()
    for instance_name, instance_data in instances.items():
        if not instance_name.isalnum or not isinstance(instance_data, dict):
            raise ValueError(f"Invalid instance name or structure for '{instance_name}'")
        
        # Additional checks for instance properties
        required_instance_properties = ["regionId", "dipToken", "dip", "portForward", "opnsenseWGPort"]
        for prop in required_instance_properties:
            if prop not in instance_data:
                raise ValueError(f"Missing required property '{prop}' in instance '{instance_name}'")

        # Additional checks for property types and values
        if not isinstance(instance_data["regionId"], str) or not instance_data["regionId"].strip():
            raise ValueError(f"'regionId' in instance '{instance_name}' must be a non-blank string")
        
        if not isinstance(instance_data["dip"], bool):
            raise ValueError(f"'dip' in instance '{instance_name}' must be a boolean (true or false)")

        if not isinstance(instance_data["portForward"], bool):
            raise ValueError(f"'portForward' in instance '{instance_name}' must be a boolean (true or false)")

        opnsenseWGPort = instance_data.get("opnsenseWGPort", "")
        if not (opnsenseWGPort.isdigit() and 1 <= int(opnsenseWGPort) <= 65535):
            raise ValueError(f"'opnsenseWGPort' in instance '{instance_name}' must be a number between 1 and 65535")
        if opnsenseWGPort in opnsenseWGPorts:
            raise ValueError(f"Duplicate opnsenseWGPort found: '{opnsenseWGPort}' in instance '{instance_name}'")
        opnsenseWGPorts.add(opnsenseWGPort)

# checks for duplicate keys
def CheckForDupKey(ordered_pairs):
    d = {}
    for k, v in ordered_pairs:
        if k in d:
           raise ValueError("duplicate key: %r" % (k,))
        else:
           d[k] = v
    return d

def CreateRequestsSession(auth, headers, verify = True):
    session = requests.Session()
    session.auth = auth
    session.headers.update({'User-Agent': 'Github: FingerlessGlov3s/OPNsensePIAWireguard'})
    if headers is not None:
        session.headers.update(headers)
    session.verify = verify # As we're connecting via local loopback we don't really need to check the certificate.
    if verify == False:
        urllib3.disable_warnings() # stop the warnings
    return session

def GetRequest(session, url, params = None):
    if not isinstance(session, requests.Session):
        raise ValueError("GET Request: Session variable not set.")
    try:
        r = session.get(url, params=params, timeout=10)
        if r.status_code == 401:
            raise ValueError("unauthorized")
        if r.status_code != 200:
            raise ValueError(f"returned non 200 status code - {r.text}")
        return r
    except ValueError as e:
        raise ValueError(f"GET Request: Failed {str(e)}")
    
def PostRequest(session, url, data):
    if not isinstance(session, requests.Session):
        raise ValueError("GET Request: Session variable not set.")
    try:
        r = session.post(url, data=json.dumps(data), headers={'Content-Type': 'application/json'}, timeout=10)
        if r.status_code == 401:
            raise ValueError("unauthorized")
        if r.status_code != 200:
            raise ValueError(f"returned non 200 status code - {r.text}")
        return r
    except ValueError as e:
        raise ValueError(f"GET Request: Failed {str(e)}")

def PIAServerList():
    try:
        url = state.serverList
        r = requests.get(url, headers={'User-Agent': 'Github: FingerlessGlov3s/OPNsensePIAWireguard'}, timeout=10)
        if r.status_code == 401:
            raise ValueError("unauthorized")
        if r.status_code != 200:
            raise ValueError(f"returned non 200 status code - {r.text}")
        return json.loads(r.text.split('\n')[0])['regions']
    except ValueError as e:
        raise ValueError(f"GET Request: Failed {str(e)}")

def PIAToken(data):
    try:
        url = state.tokenApi
        r = requests.post(url, headers={'User-Agent': 'Github: FingerlessGlov3s/OPNsensePIAWireguard', 'Content-Type': 'application/json'}, data=json.dumps(data), timeout=10)
        if r.status_code == 401:
            raise ValueError("unauthorized")
        if r.status_code != 200:
            raise ValueError(f"returned non 200 status code - {r.text}")
        return json.loads(r.text)['token']
    except ValueError as e:
        raise ValueError(f"GET Request: Failed {str(e)}")

def CheckIpInRoutes(ip, exemptNetif):
    try:
        result = subprocess.run(['netstat', '-rWnf', 'inet'], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        lines = lines[3:]
        for line in lines:
            columns = line.split()
            if len(columns) >= 6 and columns[0] == ip and columns[5] != exemptNetif:
                return True
        return False
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Error running netstat: {e}")

def InformNewIP(interfaceName):
    try:
        subprocess.run(['/usr/local/sbin/configctl', 'interface', 'newip', interfaceName, 'force'], capture_output=True, text=True, check=True)
        return True            
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Error executing command: {e}")

def GenerateFakeWGKey():
    key = secrets.token_bytes(32)
    public_key = base64.b64encode(key).decode('utf-8')
    return public_key


# Function for DNS override taken from https://stackoverflow.com/a/60751327/3927406
dns_cache = {}
# Capture a dictionary of hostname and their IPs to override with
def override_dns(domain, ip):
    """
    Adds dns entry in to dns cache dictionary, which is checked before dns lookup to allow us to override dns
    """
    dns_cache[domain] = ip
prv_getaddrinfo = socket.getaddrinfo
# Override default socket.getaddrinfo() and pass ip instead of host
# if override is detected

def new_getaddrinfo(*args):
    """
    When address information is looked up, this function is called and will provide an IP from our cache dictionary before looking it up
    """
    if args[0] in dns_cache:
        return prv_getaddrinfo(dns_cache[args[0]], *args[1:])
    return prv_getaddrinfo(*args)
socket.getaddrinfo = new_getaddrinfo

class Instance:
    def __init__(self, data, instanceName):
       self.Name = instanceName
       self.Region = data['instances'][instanceName]["regionId"]
       self.DipToken = data['instances'][instanceName]["dipToken"]
       self.Dip = data['instances'][instanceName]["dip"]
       self.PortForward = data['instances'][instanceName]["portForward"]
       self.WGPort = data['instances'][instanceName]["opnsenseWGPort"]
       self.WGUUID = ""
       self.WGPubkey = ""
       self.WGIP = "192.0.0.2"
       self.WGGateway = "192.0.0.1"
       self.WGInstance = ""
       self.WGInstanceName = f"{data['opnsenseWGPrefixName']}-{instanceName}"
       self.WGPeerName = f"{self.WGInstanceName}-server"
       self.WGPeerUUID = ""
       self.WGPeerSelected = False
       self.WGPeerPubkey = ""
       self.WGPeerPort = ""
       self.PiaPortName = f"{data['opnsenseWGPrefixName']}_{instanceName}_port"
       self.PiaPortUUID = ""
       self.RouteUUID = ""
       self.ServerChange = True
    def __str__(self):
        instance_dict = {"Instance": self.WGInstanceName}
        instance_dict.update(vars(self))
        return json.dumps(instance_dict)
    def GatewayFile(self):
        return f"/tmp/wg{self.WGInstance}_router"
    def InfoFile(self):
        return f"/tmp/wg{self.WGInstance}_piaserverinfo"
    def PortSignatureFile(self):
        return f"/tmp/wg{self.WGInstance}_piaportforwardsignature"
    def WebPortFile(self):
        return f"/usr/local/www/wg{self.WGInstance}_port.txt"


class State:
    serverList = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
    tokenApi = 'https://www.privateinternetaccess.com/api/client/v2/token'
    dedicatedIpApi = 'https://www.privateinternetaccess.com/api/client/v2/dedicated_ip'
    token = ''
    ca = os.path.join(sys.path[0], "ca.rsa.4096.crt")
    port = ''
    portSignature = ''
    metaCn = ''
    metaIp = ''
    wgCn = ''
    wgIp = ''

# Fixes bug in python requests where this env is preferred over Verify=False
if 'REQUESTS_CA_BUNDLE' in os.environ:
    del os.environ['REQUESTS_CA_BUNDLE']

# Configure the logging module
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("PIAWireGuard")

# Create an argument parser
parser = argparse.ArgumentParser(description="Python script to automate connections to PIA's WireGuard Servers. Source: https://github.com/FingerlessGlov3s/OPNsensePIAWireguard")
parser.add_argument('--debug', action='store_true', help='Enable debug logging')
parser.add_argument('--listregions', action='store_true', help='List available regions and their properties')
parser.add_argument('--changeserver', metavar='instancename', nargs='?', help='Change server for instance name or "all" for all instances')
args = parser.parse_args()

# Update the logging level based on the debug argument
if args.debug:
    logging.getLogger().setLevel(logging.DEBUG)

# Import our config file
try:
    configFile = os.path.join(sys.path[0], "PIAWireguard.json")
    if os.path.isfile(configFile):
        config = json.loads(open(configFile, 'r').read(), object_pairs_hook=CheckForDupKey)
    else:
        logger.error(f"Failed to find config file {configFile}")
        sys.exit(1)
except ValueError as e:
    logger.error(f"Failed to import config file {configFile} error: {str(e)}")
    sys.exit(1)

# Validate our config
try:
    validate_json(config)
    logger.debug("JSON validation successful.")
except ValueError as e:
    logger.error(f"JSON validation failed: {str(e)}")
    sys.exit(1)

state = State

# Check if user wanted to list regions, and if so display them
if args.listregions:
    r = requests.get(state.serverList, timeout=15)
    if r.status_code != 200:
        logger.error("Failed to get PIA server list, url is returning non 200 HTTP code, is there a connectivity issue?")
        sys.exit(2)
    piaRegions = json.loads(r.text.split('\n')[0])['regions']
    regionList = list()
    for region in piaRegions:
        regionList.append(region['name']+" | ID: "+region['id'] + " | Port forwarding: " + str(region['port_forward']) + " | Geo-located: " + str(region['geo']))
    regionList.sort() # Now we sort the list as PIA's payload isn't in region name order.
    for region in regionList:
        logger.info(region)
    logger.info("* Geo-located means these servers is not physically located in the region where the exit node is located. " +
    "The implementation of geo-located servers has provided us VPN services in countries where service may not have been " +
    "previously available due to restrictions, government legislation, or a lack of secure server providers")
    # ^ Info from https://www.privateinternetaccess.com/helpdesk/kb/articles/geo-located-servers-we-offer
    sys.exit(0)

opnsenseRequestsSession = CreateRequestsSession((config['opnsenseKey'], config['opnsenseSecret']), None, False)
try:
    logger.debug("Getting OPNsense WireGuard Instances")
    request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/server/searchServer/")
except ValueError as e:
    logger.error(f"Failed to list OPNsense WG Instances - Error message: {str(e)}")
    sys.exit(1)

logger.debug("Creating/Populating Wireguard Instances array")
wireguardInstances = json.loads(request.text)['rows']
instances_array = []
for instance_name in config.get('instances', {}):
    logger.debug(f"Setting up python script for instance {instance_name}")  
    instance_obj = Instance(config, instance_name)
    logger.debug(f"Looking for server instance {instance_obj.WGInstanceName} in gathered opnsense instances")
    for wireguardInstance in wireguardInstances:
        if wireguardInstance['name'] == instance_obj.WGInstanceName:
            instance_obj.WGUUID = wireguardInstance['uuid']
            instance_obj.WGPubkey = wireguardInstance['pubkey'].replace("=\n\n\n", '=')
            break

    if instance_obj.WGUUID == "":
        logger.debug(f"{instance_obj.Name} tunnel instance missing in OPNsense will create it.")
        logger.debug("Generating KeyPair.")
        try:
            request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/server/keyPair/")
        except ValueError as e:
            logger.error(f"KeyPair - Error message: {str(e)}")
            sys.exit(1)

        keyPair = json.loads(request.text)
        if keyPair['status'] != "ok":
            logger.error("keyPair response non ok status - trying to generate wireGuard key pair")
            sys.exit(2)
        
        logger.debug("Adding new WireGuard instance (server)")
        instance_obj.WGPubkey = keyPair['pubkey']
        createObject = {
            "server": {
                "enabled": '0',
                "name": instance_obj.WGInstanceName,
                "pubkey": keyPair['pubkey'],
                "privkey": keyPair['privkey'],
                "port": instance_obj.WGPort,
                "tunneladdress": instance_obj.WGIP,
                "disableroutes": '1',
                "gateway": instance_obj.WGGateway,
                }
        }

        try:
            request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/server/addServer/", createObject)
        except ValueError as e:
            logger.error(f"Add Instance (server) - Error message: {str(e)}")
            sys.exit(1)
        addServer = json.loads(request.text)
        if addServer['result'] != 'saved':
            logger.error(f"WireGuard creating Instance (server) - failed to add {json.dumps(addServer)}")
            sys.exit(1)
        instance_obj.WGUUID = addServer['uuid']

    logger.debug(f"Getting WireGuard instance for {instance_obj.Name}")
    try:
        request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/server/getServer/{instance_obj.WGUUID}")
    except ValueError as e:
        logger.error(f"WireGuard instance - Error message: {str(e)}")
        sys.exit(1)
    
    wireguardInstanceInfo = json.loads(request.text)['server']
    instance_obj.WGInstance = wireguardInstanceInfo["instance"]
    instance_obj.WGGateway = wireguardInstanceInfo["gateway"]
    for peer in wireguardInstanceInfo['peers']:
        if wireguardInstanceInfo['peers'][peer]['selected'] == 1:
            instance_obj.WGPeerUUID = peer
    
    if instance_obj.WGPeerUUID == '':
        logger.debug("Creating missing peer (PIA's Server)")
        createObject = {
            "client": {
                "enabled": '1',
                "name": instance_obj.WGPeerName,
                "pubkey": GenerateFakeWGKey(), # placeholder key
                "tunneladdress": "0.0.0.0/0",
                "keepalive ": '25',
                "servers": instance_obj.WGUUID
            }
        }
        try:
            request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/client/addClient/", createObject)
        except ValueError as e:
            logger.error(f"WireGuard creating peer - Error message: {str(e)}")
            sys.exit(1)
        addClient = json.loads(request.text)
        if addClient['result'] != 'saved':
            logger.error(f"WireGuard creating peer - failed to add {json.dumps(addClient)}")
            sys.exit(1)
        instance_obj.WGPeerUUID = addClient['uuid']
    else:
        logger.debug("Getting peer details (PIA's Server)")
        try:
            request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/client/getClient/{instance_obj.WGPeerUUID}")
        except ValueError as e:
            logger.error(f"getClient - Error message: {str(e)}")
            sys.exit(1)
        
        # Update payload and remove unneeded bits
        wireguardPeerInstanceInfo = json.loads(request.text)['client']
        instance_obj.WGPeerPubkey = wireguardPeerInstanceInfo['pubkey']
    
    logger.debug(f"Finished getting {instance_name} tunnel instance information from OPNsense")

    instances_array.append(instance_obj)

logger.debug("Checking handshakes")
try:
    request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/service/show/")
except ValueError as e:
    logger.error(f"Getting handshakes - Error message: {str(e)}")
    sys.exit(1)

# Workout which tunnels need to change server, if requested or handshake too old
currentEpoch = int(time.time())
peers = json.loads(request.text)["rows"]
for instance_obj in instances_array:
    for peer in peers:
        if peer['public-key'] == instance_obj.WGPeerPubkey:
            secondsDifferent = currentEpoch - peer['latest-handshake']
            if secondsDifferent > 190:
                logger.debug(f"{instance_obj.Name} tunnel down - last handshake {str(secondsDifferent)} seconds ago")
                instance_obj.ServerChange = True
            elif args.changeserver == instance_obj.Name or args.changeserver == 'all':
                logger.debug(f"{instance_obj.Name} tunnel forced change server requested")
                instance_obj.ServerChange = True
            else:
                logger.debug(f"{instance_obj.Name} tunnel up - last handshake {str(secondsDifferent)} seconds ago")
                instance_obj.ServerChange = False
    if instance_obj.ServerChange is False and os.path.isfile(instance_obj.GatewayFile()) is False:
        logger.debug(f"{instance_obj.Name} tunnel gateway file missing, change server requested")
        instance_obj.ServerChange = True

# Populate PIA server list
if any(instance_obj.ServerChange for instance_obj in instances_array):
    try:
        serverList = PIAServerList()
    except ValueError as e:
        logger.debug(f"Failed to get PIA Server List: {str(e)}")
        sys.exit(1)

# Get PIA API Token if needed for DIP
for instance_obj in instances_array:
    if instance_obj.ServerChange == False:
        continue
    if instance_obj.Dip:
        createObject = {
            "username": config['piaUsername'],
            "password": config['piaPassword']
        }
        logger.debug("Getting PIA Auth Token as required for DIP")
        try:
            piaToken = PIAToken(createObject)
        except ValueError as e:
            logger.debug(f"Failed to get PIA Token: {str(e)}")
            sys.exit(1)
        piaAuthHeaders = {
            "Authorization": f"Token {piaToken}",
            "content-type": "application/json"
        }
        dipSession = CreateRequestsSession(None, piaAuthHeaders, "/etc/ssl/cert.pem")
        break # Only need one set of details

# Now we process each instance that needs the server changing
for instance_obj in instances_array:
    if instance_obj.ServerChange == False:
        continue
    logger.debug(f"Changing server for tunnel instance {instance_obj.Name}")

    # Clear state
    state.port = ''
    state.portSignature = ''
    state.metaCn = ''
    state.metaIp = ''
    state.wgCn = ''
    state.wgIp = ''
    # If DIP we need to login to the PIA global API and get the DIP info.
    # First we authenicate then ask the DIP API for it's details.
    if instance_obj.Dip:
        logger.debug("Gathering DIP Details")
        piaDip = {
            "tokens": [instance_obj.DipToken]
        }
        logger.debug("Gathering PIA DIP Details")
        try:
            request = PostRequest(dipSession, state.dedicatedIpApi, piaDip)
        except ValueError as e:
            logger.debug(f"Failed to get DIP Details: {str(e)}")
            sys.exit(1)
        dipDetails = json.loads(request.text)[0]
        logger.debug(f"Dip Details: {dipDetails}")
        if dipDetails['status'] != "active":
            logger.error("PIA DIP isn't active")
            sys.exit(2)

        state.wgCn = dipDetails['cn']
        state.wgIp = dipDetails['ip']

        # The DIP will belong to a region, so we need to find current region's meta server from the global server list.
        for region in serverList:
            if region['id'] == dipDetails['id']:
                state.metaCn = region['servers']['meta'][0]['cn']
                state.metaIp = region['servers']['meta'][0]['ip']

        # couldn't find region, make sure the piaRegionId is set correctly
        if state.metaCn == '':
            logger.error("region not found in serverlist for DIP, is there an issue with the DIP?")
            sys.exit(2)
    else:
        # Look for a pia server in the region we want.
        # PIA API will give us one server per region, PIA will try give us the best one
        for region in serverList:
            if region['id'] == instance_obj.Region:
                state.metaCn = region['servers']['meta'][0]['cn']
                state.metaIp = region['servers']['meta'][0]['ip']
                state.wgCn = region['servers']['wg'][0]['cn']
                state.wgIp = region['servers']['wg'][0]['ip']

        # couldn't find region, make sure the piaRegionId is set correctly
        if state.metaCn == '':
            logger.error(f"region {instance_obj.Region} not found, is the correct region for the instance set")
            sys.exit(2)

    logger.debug(f"metaServer: {state.metaCn} {state.metaIp}")
    logger.debug(f"wgServer: {state.wgCn} {state.wgIp}")

    # If DUAL WAN, some people want to force a gateway
    if config["tunnelGateway"] is not None:
        logger.debug("tunnelGateway has been configured, will setup static route for PIA tunnel, to enforce outgoing gateway")
        try:
            request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/routes/routes/searchRoute/")
        except ValueError as e:
            logger.error(f"searchRoute - Error message: {str(e)}")
            sys.exit(1)

        opnsenseRoutes = json.loads(request.text)['rows']
        opnsenseRouteUUID = ''
        for route in opnsenseRoutes:
            if route['descr'] == instance_obj.WGPeerName:
                opnsenseRouteUUID = route['uuid']
                break
        
        # if the PIA server route can't be found create it
        routeUpdated = False
        if opnsenseRouteUUID == '':
            logger.debug("Creating static route as does not exist")
            createObject = {
                "route": {
                    "disabled": '0',
                    "network": state.wgIp + '/32',
                    "gateway": config['tunnelGateway'],
                    "descr": instance_obj.WGPeerName
                }
            }
            try:
                request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/routes/routes/addRoute/", createObject)
            except ValueError as e:
                logger.error(f"addRoute - Error message: {str(e)}")
                sys.exit(1)
            addRoute = json.loads(request.text)
            if addRoute['result'] != "saved":
                logger.error(f"addRoute - Error message: {str(addRoute)}")
                sys.exit(1)
            routeUpdated = True
        else:
            try:
                request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/routes/routes/getRoute/{opnsenseRouteUUID}")
            except ValueError as e:
                logger.error(f"getRoute - Error message: {str(e)}")
                sys.exit(1)
            currentRoute = json.loads(request.text)
            currentRoutedIP = currentRoute['route']['network']
            for gateway in currentRoute['route']['gateway']:
                if currentRoute['route']['gateway'][gateway]['selected'] == 1:
                    currentGateway = gateway
            
            logger.debug(f"Current Gateway: {str(currentGateway)} - Required Gateway: {str(config['tunnelGateway'])}")
            logger.debug(f"Current Routed IP: {str(currentRoutedIP)} - Required Routed IP: {str(state.wgIp)}")
            if currentGateway is not config['tunnelGateway'] or currentRoutedIP is not state.wgIp:
                logger.debug("Static route requires updating")
                currentRoute['route']['network'] = state.wgIp+'/32'
                currentRoute['route']['gateway'] = config['tunnelGateway']
                currentRoute['route']['disabled'] = 0
                try:
                    request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/routes/routes/setRoute/{opnsenseRouteUUID}", currentRoute)
                except ValueError as e:
                    logger.error(f"setRoute - Error message: {str(e)}")
                    sys.exit(1)
                setRoute = json.loads(request.text)
                if setRoute['result'] != "saved":
                    logger.error(f"setRoute - Error message: {str(setRoute)}")
                    sys.exit(1)
                routeUpdated = True
    
        if routeUpdated:
            createObject = {}
            try:
                request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/routes/routes/reconfigure/", createObject)
            except ValueError as e:
                logger.error(f"route reconfigure - Error message: {str(e)}")
                sys.exit(1)
            reconfigure = json.loads(request.text)
            if reconfigure['status'] != "ok":
                logger.error(f"route reconfigure - Error message: {str(reconfigure)}")
                sys.exit(1)
            logger.debug(f"PIA tunnel ip {state.wgIp} now set to route over WAN gateway {config['tunnelGateway']} via static route")
    # If non DIP get meta auth token
    if instance_obj.Dip == False:
        # Get PIA token from wanted region server - Tokens lasts 24 hours, so we can make our requests for a WG connection information and port is required
        # because PIA use custom certs which just have a SAN of their name eg london401, we have to put a temporary dns override in, to make it so london401 points to the meta IP
        override_dns(state.metaCn, state.metaIp)
        piaMetaSession = CreateRequestsSession((config['piaUsername'], config['piaPassword']), None, state.ca)

        try:
            request = GetRequest(piaMetaSession, f"https://{state.metaCn}/authv3/generateToken")
        except ValueError as e:
            logger.error(f"Meta generateToken - Error message: {str(e)}")
            sys.exit(1)
        state.token = json.loads(request.text)['token']

        logger.debug(f"Your PIA Token (Meta), DO NOT GIVE THIS TO ANYONE: {state.token}")

    # Now we have our PIA details, we can now request our WG connection information
    # because PIA use custom certs which just have a SAN of their name eg london401, we have to put a temporary dns override in, to make it so london401 points to the wg IP
    override_dns(state.wgCn, state.wgIp)
    # Get PIA wireguard server connection information
    
    # If we're using a DIP we need to authenicate using DIP token, otherwise used the PIA Token
    if instance_obj.Dip:
        piaMetaSession = CreateRequestsSession((f"dedicated_ip_{instance_obj.DipToken}",state.wgIp), None, state.ca)
        createObject = {
            "pubkey": instance_obj.WGPubkey
        }
        try:
            request = GetRequest(piaMetaSession, f"https://{state.wgCn}:1337/addKey", createObject)
        except ValueError as e:
            logger.error(f"addKey DIP - Error message: {str(e)}")
            sys.exit(1)
    else:
        piaMetaSession = CreateRequestsSession(None, None, state.ca)
        createObject = {
            "pt": state.token,
            "pubkey": instance_obj.WGPubkey
        }
        try:
            request = GetRequest(piaMetaSession, f"https://{state.wgCn}:1337/addKey", createObject)
        except ValueError as e:
            logger.error(f"addKey non-DIP - Error message: {str(e)}")
            sys.exit(1)
    wireguardServerInfo = json.loads(request.text)

    # We must check if the gateway IP given by PIA isn't already in use by another tunnel.
    if CheckIpInRoutes(wireguardServerInfo['server_vip'], f"wg{instance_obj.WGInstance}"):
        logger.error(f"{instance_obj.Name} encountered a problem")
        logger.error(f"The new gateway IP {wireguardServerInfo['server_vip']} is an exact match for at least one current route, can not configure this tunnel, will try again next time.")
        continue

    # Write wireguard connection information to file, for later use.
    # we need to add server name as well
    wireguardServerInfo['server_name'] = state.wgCn
    wireguardServerInfo['servermeta_name'] = state.metaCn
    wireguardServerInfo['servermeta_ip'] = state.metaIp
    with open(instance_obj.InfoFile(), 'w') as filetowrite:
        filetowrite.write(json.dumps(wireguardServerInfo))
        logger.debug(f"Saved wireguard server information to {instance_obj.InfoFile()}")

    # Update the server instance, get the current details
    logger.debug(f"Updating server instance: {instance_obj.WGInstanceName}")
    try:
        request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/server/getServer/{instance_obj.WGUUID}")
    except ValueError as e:
        logger.error(f"getServer - Error message: {str(e)}")
        sys.exit(1)
    
    # Update payload and remove unneeded bits
    wireguardInstanceInfo = json.loads(request.text)
    wireguardInstanceInfo['server']['enabled'] = '1'
    wireguardInstanceInfo['server']['dns'] = ''
    wireguardInstanceInfo['server']['gateway'] = wireguardServerInfo['server_vip']
    wireguardInstanceInfo['server']['peers'] = instance_obj.WGPeerUUID
    wireguardInstanceInfo['server']['port'] = instance_obj.WGPort
    wireguardInstanceInfo['server']['tunneladdress'] = wireguardServerInfo['peer_ip'] + '/32' # need to add /32 so it does not expand to /8
    del wireguardInstanceInfo['server']['instance'] # remove this as its not required in the request
    if 'carp_depend_on' in wireguardInstanceInfo['server'].keys(): 
        del wireguardInstanceInfo['server']['carp_depend_on']

    # Update server instance 
    try:
        request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/server/setServer/{instance_obj.WGUUID}", wireguardInstanceInfo)
    except ValueError as e:
        logger.error(f"setServer - Error message: {str(e)}")
        sys.exit(1)
    logger.debug("Updated server instance")

    # Update peer instance with the pia server details
    logger.debug(f"Updating peer: {instance_obj.WGPeerName}")
    try:
        request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/client/getClient/{instance_obj.WGPeerUUID}")
    except ValueError as e:
        logger.error(f"getClient - Error message: {str(e)}")
        sys.exit(1)
    
    # Update payload and remove unneeded bits
    wireguardPeerInstanceInfo = json.loads(request.text)
    wireguardPeerInstanceInfo['client']['enabled'] = '1'
    wireguardPeerInstanceInfo['client']['serveraddress'] = wireguardServerInfo['server_ip']
    wireguardPeerInstanceInfo['client']['serverport'] = wireguardServerInfo['server_port']
    wireguardPeerInstanceInfo['client']['pubkey'] = wireguardServerInfo['server_key']
    wireguardPeerInstanceInfo['client']['tunneladdress'] = "0.0.0.0/0"
    wireguardPeerInstanceInfo['client']['keepalive'] = "25"
    wireguardPeerInstanceInfo['client']['servers'] = instance_obj.WGUUID

    # Update peer instance 
    try:
        request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/client/setClient/{instance_obj.WGPeerUUID}", wireguardPeerInstanceInfo)
    except ValueError as e:
        logger.error(f"setClient - Error message: {str(e)}")
        sys.exit(1)
    logger.debug(f"Updated peer")    

    # Apply and enable WireGuard changes.
    # First enable WireGuard if its not
    logger.debug(f"Checking WireGuard service enabled")
    try:
        request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/general/get")
    except ValueError as e:
        logger.error(f"wireguard/general/get - Error message: {str(e)}")
        sys.exit(1)
    wgService = json.loads(request.text)
    if wgService['general']['enabled'] != '1':
        logger.debug(f"Enabling WireGuard service")
        createObject = {
            "general": {
                "enabled": '1'
            }
        }
        try:
            request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/general/set", createObject)
        except ValueError as e:
            logger.error(f"set wireguard ON - Error message: {str(e)}")
            sys.exit(1)
    
    ## Tell WireGuard to update it's config
    createObject = {}
    try:
        request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/wireguard/service/reconfigure", createObject)
    except ValueError as e:
        logger.error(f"wireguard reconfigure - Error message: {str(e)}")
        sys.exit(1)
    
    # When a dynmatic gateway is used, we need to set the gateway in a tmp file, so OPNsense gateway can pickup on it
    # https://docs.opnsense.org/manual/gateways.html#missing-dynamic-gateway
    with open(instance_obj.GatewayFile(), 'w') as filetowrite:
        filetowrite.write(wireguardServerInfo['server_vip'])
        logger.debug(f"Saved server_vip to {instance_obj.GatewayFile()}")

    # Tell OPNsense there's an new IP on the interface.
    # Have to run this twice, bugged action on OPNsense I believe.
    try:
        InformNewIP(f"wg{instance_obj.WGInstance}")
        InformNewIP(f"wg{instance_obj.WGInstance}")
    except ValueError as e:
        logger.error(f"InformNewIP - Error message: {str(e)}")
        sys.exit(1)

    ### Tunnel has been pointed to new PIA Server
    logger.debug(f"Tunnel instance {instance_obj.Name} has been changed to a new PIA server")

#
# Port forward section
# Note the tunnel must be up for the port forward requests to work, as they go over the tunnel
#    
# We need to wait if we had to changed server
if any(instance.PortForward and instance.ServerChange for instance in instances_array):
    logger.debug("Waiting 10 seconds for new WireGuard server(s) to apply before applying port forwarding")
    time.sleep(10)

# check each instance for portforwarding
for instance_obj in instances_array:
    if instance_obj.PortForward == False:
        continue

    logger.debug(f"Processing port forward for tunnel instance {instance_obj.Name}")

    # Declare some bits
    wireguardSignature = None
    wireguardServerInfo = None
    newPortRequired = False
    portRefresh = False
    state.token = ""

    getSignatureRequestsSession = CreateRequestsSession(None, None, state.ca)

    # If server change force new port
    if instance_obj.ServerChange:
        newPortRequired = True

    # first we need to check if we have a port forward signature.
    if os.path.isfile(instance_obj.PortSignatureFile()):
        wireguardSignature = json.loads(open(instance_obj.PortSignatureFile(), 'r').read())
    else:
        newPortRequired = True
    
    # get wireguard Server information
    if os.path.isfile(instance_obj.InfoFile()):
        wireguardServerInfo = json.loads(open(instance_obj.InfoFile(), 'r').read())
    else:
        logger.debug(f"wireguard server information missing for port forward {instance_obj.InfoFile()}")
        sys.exit(2)
    
    # store retrieved port in this file, so external services can easily get it
    if os.path.isfile(instance_obj.WebPortFile()) is False:
        newPortRequired = True
        logger.debug("Port not allocated, shall request port")

    # We'll check the expiry of the port, and if its expired
    if wireguardSignature is not None and newPortRequired is False:
        expiryDate = wireguardSignature['expires_at']
        if '.' in expiryDate:
            expiryDate = expiryDate.split('.')[0].replace("T", " ").replace("Z", "")
        port_expiry = datetime.datetime.strptime(expiryDate, '%Y-%m-%d %H:%M:%S')
        time_between = port_expiry - datetime.datetime.now()
        logger.debug(f"Days left on port: {str(time_between.days)}")
        if time_between.days <= 1: # if we have 1 day to go on the port, we shall request a new port
            logger.debug("port expired, shall request new port")
            newPortRequired = True
        secondsDifferent = currentEpoch - wireguardSignature['refresh_epoch']
        logger.debug(f"last port refresh {str(secondsDifferent)} seconds ago (will refresh when over 599)")
        if secondsDifferent > 599:
            portRefresh = True
            logger.debug("port refresh required")
    
    # first of we need to get a signature, signature lasts two months, we so only need to get it on serverChange. Server policy for reboots is every 2-3 months anyway
    # Might be a good idea to set cron to change PIA server every 2 month anyway
    if newPortRequired:
        # Port refresh required to scheduled the Wireguard server adding the port.
        portRefresh = True
        # get a new piatoken if we are renewing the port
        override_dns(wireguardServerInfo['servermeta_name'], wireguardServerInfo['servermeta_ip'])
        piaMetaSession = CreateRequestsSession((config['piaUsername'], config['piaPassword']), None, state.ca)
        try:
            request = GetRequest(piaMetaSession, f"https://{wireguardServerInfo['servermeta_name']}/authv3/generateToken")
        except ValueError as e:
            logger.error(f"Meta generateToken - Error message: {str(e)}")
            sys.exit(1)
        state.token = json.loads(request.text)['token']

        createObject = {
            "token": state.token
        }

        override_dns(wireguardServerInfo['server_name'], wireguardServerInfo['server_vip'])
        # make a request to the WG server VIP and get our signature
        try:
            request = GetRequest(getSignatureRequestsSession, f"https://{wireguardServerInfo['server_name']}:19999/getSignature", createObject)
        except ValueError as e:
            logger.error(f"getSignature - Error message: {str(e)}")
            sys.exit(1)
        wireguardSignature = json.loads(request.text)
        logger.debug(f"PIA Signature Port: {request.text}")

        if wireguardSignature['status'] != 'OK':
            logger.error("wireguardSignature status came back with not OK")
            sys.exit(2)

        payloadInfo = json.loads(base64.b64decode(wireguardSignature['payload']))
        logger.debug(f"PayloadInfo {payloadInfo}")
        wireguardSignature['expires_at'] = payloadInfo['expires_at']
        wireguardSignature['port'] = payloadInfo['port']

        with open(instance_obj.WebPortFile(), 'w') as filetowrite:
            filetowrite.write(str(payloadInfo['port']))
            logger.debug(f"Saved port number to {instance_obj.WebPortFile()}")
        # written port to file
    
    # The requested port has a timer that needs to be refresh so you can keep the port active.
    # Must be refreshed atleast every 15 minutes.
    # We'll also update the firewall alias during this step
    if portRefresh:
        createObject = {
            "payload": wireguardSignature['payload'],
            "signature": wireguardSignature['signature']
        }
        override_dns(wireguardServerInfo['server_name'], wireguardServerInfo['server_vip'])
        # make a request to the WG server VIP and get our signature
        try:
            request = GetRequest(getSignatureRequestsSession, f"https://{wireguardServerInfo['server_name']}:19999/bindPort", createObject)
        except ValueError as e:
            logger.error(f"bindPort - Error message: {str(e)}")
            sys.exit(1)
        wireguardPort = json.loads(request.text)
        logger.debug(f"PIA Port Request: {request.text}")

        if wireguardPort['status'] != 'OK':
            if os.path.isfile(instance_obj.WebPortFile()):
                os.remove(instance_obj.WebPortFile())
                logger.error("Removed port file because status is no longer ok status returned from port refresh, will attempt new port next time")
        
        # save required information to file for next time
        wireguardSignature['refresh_epoch'] = currentEpoch
        with open(instance_obj.PortSignatureFile(), 'w') as filetowrite:
            filetowrite.write(json.dumps(wireguardSignature))
            logger.debug(f"Saved wireguardSignature and payload to {instance_obj.PortSignatureFile()}")

    # If new port then we update the alias
    if newPortRequired:
        # check if the PIA port forward alias exists
        opnsensePiaPortUpdated = False
        opnsensePiaPortUUID = ''
        try:
            request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/firewall/alias/getAliasUUID/{instance_obj.PiaPortName}")
        except ValueError as e:
            logger.error(f"getAliasUUID - Error message: {str(e)}")
            sys.exit(1)
        piaPortAlias = json.loads(request.text)
        if piaPortAlias:
            opnsensePiaPortUUID = piaPortAlias['uuid']

        # Now we know if its does or does not exist, we can create/update it
        if opnsensePiaPortUUID == '':
            createObject = {
                "alias": {
                    "enabled": '1',
                    "name": instance_obj.PiaPortName,
                    "description": f"PIA Port forwarded, port from WireGuard PIA instance {instance_obj.Name}",
                    "type": "port",
                    "content": wireguardSignature['port']
                    }
                }
            try:
                request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/firewall/alias/addItem/", createObject)
            except ValueError as e:
                logger.error(f"addItem alias - Error message: {str(e)}")
                sys.exit(1)
            opnsensePiaPortUpdated = True
        else:
            # get current port alias information, so we can check its the right port
            try:
                request = GetRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/firewall/alias/getItem/{opnsensePiaPortUUID}")
            except ValueError as e:
                logger.error(f"getAliasUUID - Error message: {str(e)}")
                sys.exit(1)
            piaPortAlias = json.loads(request.text)
            currentAliasPort = "0"
            for port in piaPortAlias['alias']['content']:
                if piaPortAlias['alias']['content'][port]['selected'] == 1:
                    currentAliasPort = piaPortAlias['alias']['content'][port]['value']

            logger.debug(f"CurrentPortInAlias: {str(currentAliasPort)}")
            logger.debug(f"Required Port: {str(wireguardSignature['port'])}")
            if currentAliasPort != str(wireguardSignature['port']):
                logger.debug("Ports don't match shall correct the Alias")
                piaPortAlias['alias']['content'] = wireguardSignature['port']
                piaPortAlias['alias']['type'] = 'port'
                piaPortAlias['alias']['counters'] = ''
                piaPortAlias['alias']['proto'] = ''
                piaPortAlias['alias']['interface'] = ''
                if 'categories' in piaPortAlias['alias'].keys(): 
                    del piaPortAlias['alias']['categories']
                try:
                    request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/firewall/alias/setItem/{opnsensePiaPortUUID}", piaPortAlias)
                except ValueError as e:
                    logger.error(f"setItem alias - Error message: {str(e)}")
                    sys.exit(1)
                setItem = json.loads(request.text)
                if setItem['result'] != 'saved':
                    logger.error(f"setItem alias - Error message: {str(e)}")
                    sys.exit(1)
                opnsensePiaPortUpdated = True
            else:
                logger.debug("No port update required in OPNsense")

        # If update reload firewall aliases
        if opnsensePiaPortUpdated:
            logger.debug("Applying updated alias changes")
            createObject = {}
            try:
                request = PostRequest(opnsenseRequestsSession, f"{config['opnsenseURL']}/api/firewall/alias/reconfigure", createObject)
            except ValueError as e:
                logger.error(f"reconfigure aliases - Error message: {str(e)}")
                sys.exit(1)
            reconfigure = json.loads(request.text)
            if reconfigure['status'] != 'ok':
                logger.error(f"reconfigure aliases - Error message: {str(e)}")
                sys.exit(1)
            
    logger.debug(f"Finished processing port forward for tunnel instance {instance_obj.Name}")

logger.debug("Finished")
sys.exit(0)
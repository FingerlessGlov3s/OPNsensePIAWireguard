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

import time
import os
import socket
import sys
import base64
import datetime
import json
import urllib3
import requests
import re

#
# Please see PIAWireguard.json for configuration settings
#


#
# Script Start
#

# Import our config file
try:
    configFile = os.path.join(sys.path[0], "PIAWireguard.json")
    if os.path.isfile(configFile):
        config = json.loads(open(configFile, 'r').read())
    else:
        print(f"Failed to find config file {configFile}")
        sys.exit(1)
except:
    print(f"Failed to import config file {configFile}")
    sys.exit(1)

requiredConfig = [
    "opnsenseURL",
    "opnsenseKey",
    "opnsenseSecret",
    "opnsenseWGName",
    "opnsenseWGPort",
    "piaUsername",
    "piaPassword",
    "piaRegionId",
    "piaDipToken",
    "piaPortForward",
    "piaUseDip",
    "tunnelGateway"
]

# Check config contains the right settings
if requiredConfig.sort() != list(config.keys()).sort():
    print("Your config json is missing some settings, please check it against the repo.")
    sys.exit(1)

# Define used variables used throughout the script
opnsenseWGUUID = ""
opnsenseWGPubkey = ""
opnsenseWGIP = "192.0.0.2"
opnsenseWGGateway = "192.0.0.1"
opnsenseWGInstance = ""
opnsenseWGPeerName = f"{config['opnsenseWGName']}-Server"
opnsenseWGPeerUUID = ""
opnsenseWGPeerSelected = False
opnsenseWGPeerPubkey = ""
opnsenseWGPeerPort = ""
opnsensePiaPortName = f"{config['opnsenseWGName']}_Port"
opnsensePiaPortUUID = ""
opnsenseRouteUUID = ""

piaServerList = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
piaTokenApi = 'https://www.privateinternetaccess.com/api/client/v2/token'
piaDedicatedIpApi = 'https://www.privateinternetaccess.com/api/client/v2/dedicated_ip'
piaToken = ''
piaCA = os.path.join(sys.path[0], "ca.rsa.4096.crt")
piaPort = ''
piaPortSignature = ''
piaMetaCn = ''
piaMetaIp = ''
piaWgCn = ''
piaWgIp = ''
urlVerify = False # As we're connecting via local loopback I guess we don't really need to check the certificate. (I've noticed alot of people have the default self sigend anyway)

helpArg = False
debugMode = False
listRegions = False
serverChange = False

# Disable HTTPS verify warnings when Verify turned off
if urlVerify is False:
    urllib3.disable_warnings()
# Process any args added to the script
if len(sys.argv) > 1:
    for arg in sys.argv:
        if arg.lower() == "help":
            helpArg = True
        if arg.lower() == "debug":
            debugMode = True
        if arg.lower() == "listregions":
            listRegions = True
        if arg.lower() == "changeserver":
            serverChange = True

#
# Functions
#

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

# Debug Print
def printDebug(text):
    """
    Allows us to easily print debugging information when debug param is used
    """
    if debugMode:
        print(text)

#
# Script logic
#

if helpArg:
    print("Commands:")
    print("")
    print("PIAWireguard.py                    Runs script normally")
    print("PIAWireguard.py help               Help text (This)")
    print("PIAWireguard.py debug              Runs script with verbose output of the script")
    print("PIAWireguard.py listregions        Lists usable PIA regions for the script")
    print("PIAWireguard.py changeserver       Reconnect to a new PIA server")
    print("")
    print("Source: https://github.com/FingerlessGlov3s/OPNsensePIAWireguard")
    sys.exit(0)

# Check if user wanted to list regions, and if so display them
if listRegions:
    r = requests.get(piaServerList)
    if r.status_code != 200:
        print("Failed to get PIA server list, url is returning non 200 HTTP code, is there a connectivity issue?")
        sys.exit(2)
    piaRegions = json.loads(r.text.split('\n')[0])['regions']
    regionList = list()
    for region in piaRegions:
        regionList.append(region['name']+" | ID: "+region['id'] + " | Port forwarding: " + str(region['port_forward']) + " | Geo-located: " + str(region['geo']))
    regionList.sort() # Now we sort the list as PIA's payload isn't in region name order.
    for region in regionList:
        print(region)
    print("* Geo-located means these servers is not physically located in the region where the exit node is located. " +
    "The implementation of geo-located servers has provided us VPN services in countries where service may not have been " +
    "previously available due to restrictions, government legislation, or a lack of secure server providers")
    # ^ Info from https://www.privateinternetaccess.com/helpdesk/kb/articles/geo-located-servers-we-offer
    sys.exit(0)

if config['opnsenseKey'] == '':
    print("Please define opnsenseKey variable with the correct value in the json file")
    sys.exit(0)

if config['opnsenseSecret'] == '':
    print("Please define opnsenseSecret variable with the correct value in the json file")
    sys.exit(0)

if config['piaUsername'] == '':
    print("Please define piaUsername variable with the correct value in the json file")
    sys.exit(0)

if config['piaPassword'] == '':
    print("Please define piaPassword variable with the correct value in the json file")
    sys.exit(0)

if config['opnsenseURL'] == '':
    print("Please define opnsenseURL variable with the correct value in the json file")
    sys.exit(0)

if config['piaUseDip'] == True and config['piaDipToken'] == '':
    print("If you wish to use PIA Dedicated IP, please supply DIP Token in piaDipToken")
    sys.exit(0)

if config['piaUseDip'] != True and config['piaUseDip'] != False:
    print("piaUseDip can only be true or false")
    sys.exit(0)

if config['opnsenseWGName'] == '' or not re.search("^([0-9a-zA-Z._\-]){1,64}$", config['opnsenseWGName']):
    print("Please define opnsenseWGName variable with the correct value in the json file. " +
    "Should be a string between 1 and 64 characters. Allowed characters are alphanumeric characters, dash and underscores.")
    sys.exit(0)

opnsenseURL = config['opnsenseURL']

# List current wireguard instances looking for PIA one
try:
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/searchServer/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
except:
    print(f"Failed to connect to {opnsenseURL}, perhaps you've changed the WebUI port please append it (opnsenseURL) EG: https://127.0.0.1:8443")
    sys.exit(2)
if r.status_code == 401:
    print("searchServer request unauthorized, please check permissions and API keys")
    sys.exit(2)
if r.status_code != 200:
    print("searchServer request failed non 200 status code - listing wireguard instances")
    sys.exit(2)

wireguardInstances = json.loads(r.text)['rows']

for instance in wireguardInstances:
    if instance['name'] == config['opnsenseWGName']:
        opnsenseWGUUID = instance['uuid']
        opnsenseWGPubkey = instance['pubkey'].replace("=\n\n\n", '=')
        break

# if the PIA WG instance doesn't exist we'll create it.
if opnsenseWGUUID == '':
    # Generate a key pair for the server
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/keyPair/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("keyPair request filed non 200 status code - trying to generate wireGuard key pair")
        sys.exit(2)

    keyPair = json.loads(r.text)
    if keyPair['status'] != "ok":
        print("keyPair response non ok status - trying to generate wireGuard key pair")
        sys.exit(2)

    createObject = {
        "server": {
            "enabled": '1',
            "name": config['opnsenseWGName'],
            "pubkey": keyPair['pubkey'],
            "privkey": keyPair['privkey'],
            "port": config['opnsenseWGPort'],
            "tunneladdress": opnsenseWGIP,
            "disableroutes": '1',
            "gateway": opnsenseWGGateway,
            }
    }
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/addServer/', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("addServer request failed non 200 status code - trying to add wireGuard Instance")
        sys.exit(2)

    # get UUID of the PIA WG instance now its created
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/searchServer/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("searchServer request failed non 200 status code - getting our PIA instance GUID")
        sys.exit(2)

    wireguardInstances = json.loads(r.text)

    for instance in wireguardInstances['rows']:
        if instance['name'] == config['opnsenseWGName']:
            opnsenseWGUUID = instance['uuid']
            opnsenseWGPubkey = instance['pubkey'].replace("=\n\n\n", '=')
            break

# Get PIA WG instance information, so we can check if the PIA client (peer) has been added
r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{opnsenseWGUUID}', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
if r.status_code != 200:
    print("getServer request failed non 200 status code - getting PIA server information")
    sys.exit(2)

wireguardInstanceInfo = json.loads(r.text)['server']
opnsenseWGInstance = wireguardInstanceInfo['instance'] # get instance number for working out wg0 interface name etc, later on
for peer in wireguardInstanceInfo['peers']:
    if wireguardInstanceInfo['peers'][peer]['selected'] == 1:
        opnsenseWGPeerUUID = peer
        opnsenseWGPeerSelected = True

# If client (peer) not found in the instance, look for it, to see if it just needs adding
if opnsenseWGPeerSelected is False:
    # List current WG clients(peers) looking for PIA one, so we can add it.
    r = requests.get(f'{opnsenseURL}/api/wireguard/client/searchClient/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("searchClient request failed non 200 status code - listing wireguard clients")
        sys.exit(2)

    wireguardsClients = json.loads(r.text)['rows']
    for client in wireguardsClients:
        if client['name'] == opnsenseWGPeerName:
            opnsenseWGPeerUUID = client['uuid']
            break

# if the PIA WG client (peer) can't be found create it.
if opnsenseWGPeerUUID == '':
    createObject = {
        "client": {
            "enabled": '1',
            "name": opnsenseWGPeerName,
            "pubkey": "WhCLp1jt2QfcCRYHP63++tGwdSvCA4B3oeOzJu5dMCM=",
            "tunneladdress": "0.0.0.0/0",
            "keepalive ": '25'
            }
    }
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/client/addClient/', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("addClient request failed non 200 status code - trying to add new wireGuard client (peer)")
        sys.exit(2)


# Now we know we have the WG client (peer) we needs its UUID and pubkey
r = requests.get(f'{opnsenseURL}/api/wireguard/client/searchClient/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
if r.status_code != 200:
    print("searchServer request failed non 200 status code - listing wireguard clients looking for newly created")
    sys.exit(2)

wireguardsClients = json.loads(r.text)['rows']
for client in wireguardsClients:
    if client['name'] == opnsenseWGPeerName:
        opnsenseWGPeerUUID = client['uuid']
        opnsenseWGPeerPubkey = client['pubkey'].replace("=\n\n\n", '=') # sometimes 3 new lines get added tp the pubkey annoyingly
        break

# Add peer if its not selected on the WG instance.
if opnsenseWGPeerSelected is False:
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{opnsenseWGUUID}', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)

    if r.status_code != 200:
        print("getServer request failed non 200 status code - adding peer to server")
        sys.exit(2)

    wireguardInstanceInfo = json.loads(r.text)
    wireguardInstanceInfo['server']['peers'] = opnsenseWGPeerUUID
    wireguardInstanceInfo['server']['dns'] = ''
    wireguardInstanceInfo['server']['tunneladdress'] = opnsenseWGIP
    del wireguardInstanceInfo['server']['instance']

    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/setServer/{opnsenseWGUUID}', data=json.dumps(wireguardInstanceInfo), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("addClient request failed non 200 status code - trying to add wireGuard client (peer) to wireguard Instance")
        sys.exit(2)

# Print some debug information
printDebug(f"WGInstanceUUID: {opnsenseWGUUID}")
printDebug(f"WGPeerUUID: {opnsenseWGPeerUUID}")

printDebug(f"WGInstance: {opnsenseWGPubkey}")
printDebug(f"WGPeer: {opnsenseWGPeerPubkey}")
if debugMode and opnsenseWGPeerPubkey == '':
    printDebug("WGPeer is blank but this isn't an issue")


# get handshake information, just need to look for the peer and see its there, we can then check when the handshake was, reported in epoch
r = requests.get(f'{opnsenseURL}/api/wireguard/service/showhandshake/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
if r.status_code != 200:
    print("showhandshake request failed non 200 status code - getting handshake information")
    sys.exit(2)

linesOfConf = json.loads(r.text)['response'].split('\n')
foundWGPeer = False
currentEpoch = int(time.time())
WGPeerHandshake = 0
for line in linesOfConf:
    line = line.strip().split('\t')
    if len(line) > 1:
        if line[1] == opnsenseWGPeerPubkey:
            WGPeerHandshake = int(line[2])

secondsDifferent = currentEpoch - WGPeerHandshake

# Inform debug when a force server change is requested
if serverChange:
    printDebug("Force server change requested")

# check number of seconds since last handshake, if its was less than 190 seconds ago, very good chance the tunnel is working fine.
if secondsDifferent < 190 and serverChange is False:
    printDebug(f"Tunnel working - last handshake {str(secondsDifferent)} seconds ago")
else:
    serverChange = True

# If OPNsense is restarted, the gateway will lose its router pointer due to being in /tmp, so if it doesn't exist we need to change server.
dynamticGatewayFile = f"/tmp/wg{opnsenseWGInstance}_router"
if os.path.isfile(dynamticGatewayFile) is False:
    serverChange = True

#
# Wireguard Server connection section
#

# If server change is required, we'll grab a server IP from the PIA API
if serverChange:
    # Get PIA Server List
    try:
        r = requests.get(piaServerList)
        if r.status_code != 200:
            print("Failed to get PIA server list, url is returning non 200 HTTP code, is there a connectivity issue?")
            sys.exit(2)
        serverList = json.loads(r.text.split('\n')[0])
    except requests.exceptions.RequestException as e:
        print("Failed to get PIA server list due to a request error:")
        print(e)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print("Failed to parse JSON response:")
        print(e)
        sys.exit(2)

    if config['piaUseDip']:
        createObject = {
            "username": config['piaUsername'],
            "password": config['piaPassword']
        }
        headers = {'content-type': 'application/json'}
        generateTokenResponse = requests.post(piaTokenApi, data=json.dumps(createObject), headers=headers)
        if generateTokenResponse.status_code != 200:
            print("wireguardserver /v2/token request failed non 200 status code - Trying to get PIA token")
            sys.exit(2)
        piaToken = json.loads(generateTokenResponse.text)['token']

        printDebug("Your PIA Token (Global), DO NOT GIVE THIS TO ANYONE")
        printDebug(generateTokenResponse.text)

        piaAuthHeaders = {
            "Authorization": f"Token {piaToken}",
            "content-type": "application/json"
        }
        piaDip = {
            "tokens": [config['piaDipToken']]
        }
        dipDetailsResponse = requests.post(piaDedicatedIpApi, data=json.dumps(piaDip),headers=piaAuthHeaders)
        if dipDetailsResponse.status_code != 200:
            print("wireguardserver /v2/dedicated_ip request failed non 200 status code - Trying to get PIA DIP details")
            sys.exit(2)
        dipDetails = json.loads(dipDetailsResponse.text)[0]
        printDebug("DIP Details")
        printDebug(dipDetails)

        if dipDetails['status'] != "active":
            print("PIA DIP isn't active")
            sys.exit(2)

        piaWgCn = dipDetails['cn']
        piaWgIp = dipDetails['ip']


        # The DIP will belong to a region, so we need to find current region's meta server from the global server list.
        for region in serverList['regions']:
            if region['id'] == dipDetails['id']:
                piaMetaCn = region['servers']['meta'][0]['cn']
                piaMetaIp = region['servers']['meta'][0]['ip']
        
        # couldn't find region, make sure the piaRegionId is set correctly
        if piaMetaCn == '':
            print("region not found, for DIP, is there an issue with the DIP?")
            sys.exit(2)
    else:
        # Look for a pia server in the region we want.
        # PIA API will give us one server per region, PIA will try give us the best one
        for region in serverList['regions']:
            if region['id'] == config['piaRegionId']:
                piaMetaCn = region['servers']['meta'][0]['cn']
                piaMetaIp = region['servers']['meta'][0]['ip']
                piaWgCn = region['servers']['wg'][0]['cn']
                piaWgIp = region['servers']['wg'][0]['ip']

        # couldn't find region, make sure the piaRegionId is set correctly
        if piaMetaCn == '':
            print("region not found, correct piaRegionId set?")
            sys.exit(2)

    # print some useful debug information about what servers
    printDebug("metaServer")
    printDebug("CN: " + piaMetaCn)
    printDebug("IP: " + piaMetaIp)
    printDebug("wgServer")
    printDebug("CN: " + piaWgCn)
    printDebug("IP: " + piaWgIp)

    # If tunnelGateway is configured we need to add the route, to force the PIA wg tunnel over the wanted WAN
    if config['tunnelGateway'] is not None:
        routeUpdated = False
        printDebug("tunnelGateway has been configured, will setup static route for PIA tunnel, to enforce outgoing gateway")
        # List current routes and check if one for PIA already exists
        r = requests.get(f'{opnsenseURL}/api/routes/routes/searchRoute/', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
        if r.status_code != 200:
            print("searchRoute request failed non 200 status code - listing routing to see if one already exists")
            sys.exit(2)

        opnsenseRoutes = json.loads(r.text)['rows']
        for route in opnsenseRoutes:
            if route['descr'] == opnsenseWGPeerName:
                opnsenseRouteUUID = route['uuid']
                break

        # if the PIA server route can't be found create it
        if opnsenseRouteUUID == '':
            createObject = {
                "route": {
                    "disabled": '0',
                    "network": piaWgIp + '/32',
                    "gateway": config['tunnelGateway'],
                    "descr": opnsenseWGPeerName
                    }
            }
            headers = {'content-type': 'application/json'}
            r = requests.post(f'{opnsenseURL}/api/routes/routes/addRoute/', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
            if r.status_code != 200:
                print("addroute request failed non 200 status code - trying to add new OPNsense route, make sure gateway name is correct")
                sys.exit(2)
            routeUpdated = True
        else:
            # get current route, check and amend if necessary
            r = requests.get(f'{opnsenseURL}/api/routes/routes/getRoute/{opnsenseRouteUUID}', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
            if r.status_code != 200:
                print("getRoute request failed non 200 status code - Getting current PIA route")
                sys.exit(2)
            currentRoute = json.loads(r.text)
            currentRoutedIP = currentRoute['route']['network']
            for gateway in currentRoute['route']['gateway']:
                if currentRoute['route']['gateway'][gateway]['selected'] == 1:
                    currentGateway = gateway

            printDebug(f"Current Tunnel Gateway: {str(currentGateway)}")
            printDebug(f"Required Tunnel Gateway: {str(config['tunnelGateway'])}")
            printDebug(f"Current Routed IP: {str(currentRoutedIP)}")
            printDebug(f"Required Routed IP: {str(piaWgIp+'/32')}")
            if currentGateway is not config['tunnelGateway'] or currentRoutedIP is not piaWgIp:
                printDebug("Route update required")
                currentRoute['route']['network'] = piaWgIp+'/32'
                currentRoute['route']['gateway'] = config['tunnelGateway']
                currentRoute['route']['disabled'] = 0

                headers = {'content-type': 'application/json'}
                r = requests.post(f'{opnsenseURL}/api/routes/routes/setRoute/{opnsenseRouteUUID}', data=json.dumps(currentRoute), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
                if r.status_code != 200:
                    print("setRoute request failed non 200 status code - trying to amend OPNsense route for PIA, make sure gateway name is correct")
                    sys.exit(2)
                routeUpdated = True
            else:
                printDebug("No PIA route update required")

        # Apply the new static route if required
        if routeUpdated:
            createObject = {}
            headers = {'content-type': 'application/json'}
            r = requests.post(f'{opnsenseURL}/api/routes/routes/reconfigure/', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
            if r.status_code != 200:
                print("reconfigure request failed non 200 status code - trying to apply PIA static route changes")
                sys.exit(2)
            printDebug(f"PIA tunnel ip now set to route over WAN gateway {config['tunnelGateway']} via static route")

    # Get PIA token from meta server for non DIP Servers
    if config['piaUseDip'] == False:
        # Get PIA token from wanted region server - Tokens lasts 24 hours, so we can make our requests for a WG connection information and port is required
        # because PIA use custom certs which just have a SAN of their name eg london401, we have to put a temporary dns override in, to make it so london401 points to the meta IP
        override_dns(piaMetaCn, piaMetaIp)
        generateTokenResponse = requests.get(f"https://{piaMetaCn}/authv3/generateToken", auth=(config['piaUsername'], config['piaPassword']), verify=piaCA)
        if generateTokenResponse.status_code != 200:
            print("wireguardserver generateToken request failed non 200 status code - Trying to get PIA token")
            sys.exit(2)
        piaToken = json.loads(generateTokenResponse.text)['token']

        printDebug("Your PIA Token (Meta), DO NOT GIVE THIS TO ANYONE")
        printDebug(generateTokenResponse.text)

    # Now we have our PIA details, we can now request our WG connection information
    # because PIA use custom certs which just have a SAN of their name eg london401, we have to put a temporary dns override in, to make it so london401 points to the wg IP
    override_dns(piaWgCn, piaWgIp)
    # Get PIA wireguard server connection information
    
    # If we're using a DIP we need to authenicate using DIP token, otherwise used the PIA Token
    wireguardResponse = None
    if config['piaUseDip']:
        createObject = {
            "pubkey": opnsenseWGPubkey
        }
        wireguardResponse = requests.get(f"https://{piaWgCn}:1337/addKey", params=createObject, auth=(f"dedicated_ip_{config['piaDipToken']}",piaWgIp), verify=piaCA)
    else:
        createObject = {
            "pt": piaToken,
            "pubkey": opnsenseWGPubkey
        }
        wireguardResponse = requests.get(f"https://{piaWgCn}:1337/addKey", params=createObject, verify=piaCA)

    if wireguardResponse.status_code != 200:
        print("wireguardserver addKey request failed non 200 status code - Trying to add instance public key to server in exchnage for connection information")
        sys.exit(2)
    wireguardServerInfo = json.loads(wireguardResponse.text)
    printDebug("WG Server connection information")
    printDebug(wireguardResponse.text)


    # Write wireguard connection information to file, for later use.
    # we need to add server name as well
    wireguardServerInfo['server_name'] = piaWgCn
    wireguardServerInfo['servermeta_ip'] = piaMetaIp
    wireguardServerInfoFile = f"/tmp/wg{opnsenseWGInstance}_piaserverinfo"
    with open(wireguardServerInfoFile, 'w') as filetowrite:
        filetowrite.write(json.dumps(wireguardServerInfo))
        printDebug(f"Saved wireguard server information to {wireguardServerInfoFile}")

    # update PIA WG instance with the new client side information
    # first we get the current settings for the WG instance
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{opnsenseWGUUID}', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("getServer request failed non 200 status code - adding peer to server")
        sys.exit(2)

    # Make our necessary changes
    wireguardInstanceInfo = json.loads(r.text)
    wireguardInstanceInfo['server']['enabled'] = '1'
    wireguardInstanceInfo['server']['peers'] = opnsenseWGPeerUUID
    wireguardInstanceInfo['server']['tunneladdress'] = wireguardServerInfo['peer_ip'] + '/32' # need to add /32 so it does not expand to /8
    wireguardInstanceInfo['server']['gateway'] = wireguardServerInfo['server_vip']
    wireguardInstanceInfo['server']['dns'] = ''
    del wireguardInstanceInfo['server']['instance'] # remove this as its not required in the request

    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/setServer/{opnsenseWGUUID}', data=json.dumps(wireguardInstanceInfo), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("setServer request failed non 200 status code - trying update WG instance to acquired PIA settings")
        sys.exit(2)

    # update PIA WG client (peer) instance, with the server side details
    r = requests.get(f'{opnsenseURL}/api/wireguard/client/getClient/{opnsenseWGPeerUUID}', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("getServer request failed non 200 status code - getting PIA WG client (peer)")
        sys.exit(2)

    wireguardPeerInstanceInfo = json.loads(r.text)
    wireguardPeerInstanceInfo['client']['enabled'] = '1'
    wireguardPeerInstanceInfo['client']['serveraddress'] = wireguardServerInfo['server_ip']
    wireguardPeerInstanceInfo['client']['serverport'] = wireguardServerInfo['server_port']
    wireguardPeerInstanceInfo['client']['pubkey'] = wireguardServerInfo['server_key']
    wireguardPeerInstanceInfo['client']['tunneladdress'] = "0.0.0.0/0"
    wireguardPeerInstanceInfo['client']['keepalive'] = "25"

    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/client/setClient/{opnsenseWGPeerUUID}', data=json.dumps(wireguardPeerInstanceInfo), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("addClient request failed non 200 status code -  trying update WG client (peer) to acquired PIA settings")
        sys.exit(2)

    # When a dynmatic gateway is used, we need to set the gateway in a tmp file, so OPNsense gateway can pickup on it
    # https://docs.opnsense.org/manual/gateways.html#missing-dynamic-gateway
    dynamticGatewayFile = f"/tmp/wg{opnsenseWGInstance}_router"
    with open(dynamticGatewayFile, 'w') as filetowrite:
        filetowrite.write(wireguardServerInfo['server_vip'])
        printDebug(f"Saved server_vip to {dynamticGatewayFile}")

    # Apply and enable WireGuard changes.
    # First enable WireGuard if its not
    createObject = {
        "general": {
            "enabled": '1'
            }
    }
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/general/set', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("turn on wireguard request failed non 200 status code - trying to enable wireguard)")
        sys.exit(2)
    # Apply the wireguard saves (save button in the interface)
    createObject = {}
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/service/reconfigure/{opnsenseWGPeerUUID}', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("reconfigure request failed non 200 status code - trying to apply all wireguard changes")
        sys.exit(2)

#
# Port forward section
# Note the tunnel must be up for the port forward requests to work, as they go over the tunnel
#

# If portforward isn't requied, exit script otherwise carry on
if config['piaPortForward'] is False:
    sys.exit(0)

if serverChange:
    print("Wait 5 seconds for new WireGuard server to apply before port forwarding")
    time.sleep(5)

# first we need to check if we have a port forward signature.
wireguardSignature = None
portForwardSignatureFile = f"/tmp/wg{opnsenseWGInstance}_piaportforwardsignature"
if os.path.isfile(portForwardSignatureFile):
    wireguardSignature = json.loads(open(portForwardSignatureFile, 'r').read())

# get wireguard Server information
wireguardServerInfo = None
wireguardServerInfoFile = f"/tmp/wg{opnsenseWGInstance}_piaserverinfo"
if os.path.isfile(wireguardServerInfoFile):
    wireguardServerInfo = json.loads(open(wireguardServerInfoFile, 'r').read())
else:
    print("wireguard server information missing for port forward")
    sys.exit(2)

# store retrieved port in this file, so external services can easily get it
piaPortFile = f"/usr/local/www/wg{opnsenseWGInstance}_port.txt"
newPortRequired = False
portRefresh = False
if os.path.isfile(piaPortFile) is False:
    newPortRequired = True
    printDebug("Port not assigned, shall request port")

# We'll check the expiry of the port, and if its expired
if wireguardSignature is not None:
    expiryDate = wireguardSignature['expires_at']
    if '.' in expiryDate:
        expiryDate = expiryDate.split('.')[0].replace("T", " ").replace("Z", "")
    port_expiry = datetime.datetime.strptime(expiryDate, '%Y-%m-%d %H:%M:%S')
    time_between = port_expiry - datetime.datetime.now()
    printDebug(f"Days left on port: {str(time_between.days)}")
    if time_between.days <= 1: # if we have 1 day to go on the port, we shall request a new port
        printDebug("port expired, shall request new port")
        newPortRequired = True
    secondsDifferent = currentEpoch - wireguardSignature['refresh_epoch']
    printDebug(f"last port refresh {str(secondsDifferent)} seconds ago (will refresh when over 599)")
    if secondsDifferent > 599:
        portRefresh = True
        printDebug("port refresh required")

# first of we need to get a signature, signature lasts two months, we so only need to get it on serverChange. Server policy for reboots is every 2-3 months anyway
# Might be a good idea to set cron to change PIA server every 2 month anyway
if serverChange or newPortRequired:
    # Port refresh required to scheduled the Wireguard server adding the port.
    portRefresh = True
    # get a new piatoken if we are renewing the port, if it a server change token will exist by this point
    if piaToken == "":
        override_dns(wireguardServerInfo['server_name'], wireguardServerInfo['servermeta_ip'])
        generateTokenResponse = requests.get(f"https://{wireguardServerInfo['server_name']}/authv3/generateToken", auth=(config['piaUsername'], config['piaPassword']), verify=piaCA)
        if generateTokenResponse.status_code != 200:
            print("wireguardserver generateToken for port forward request failed non 200 status code - Trying to get PIA token")
            sys.exit(2)
        piaToken = json.loads(generateTokenResponse.text)['token']

    createObject = {
        "token": piaToken
    }

    override_dns(wireguardServerInfo['server_name'], wireguardServerInfo['server_vip'])
    # make a request to the WG server VIP and get our signature
    wireguardSignatureResponse = requests.get(f"https://{wireguardServerInfo['server_name']}:19999/getSignature", params=createObject, verify=piaCA)
    if wireguardSignatureResponse.status_code != 200:
        print("wireguardserver getSignature request failed non 200 status code - Trying to get a port foward signature")
        sys.exit(2)
    wireguardSignature = json.loads(wireguardSignatureResponse.text)
    printDebug("PIA Signature Port")
    printDebug(wireguardSignatureResponse.text)

    if wireguardSignature['status'] != 'OK':
        print("wireguardSignature status came back with not OK")
        sys.exit(2)

    payloadInfo = json.loads(base64.b64decode(wireguardSignature['payload']))
    printDebug("PayloadInfo")
    printDebug(payloadInfo)
    wireguardSignature['expires_at'] = payloadInfo['expires_at']
    wireguardSignature['port'] = payloadInfo['port']

    with open(piaPortFile, 'w') as filetowrite:
        filetowrite.write(str(payloadInfo['port']))
        printDebug(f"Saved port number to {piaPortFile}")

# exit if portRefresh not required
if portRefresh is False:
    sys.exit(0)

# The requested port has a timer that needs to be refresh so you can keep the port.
# Must be refreshed atleast every 15 minutes.
createObject = {
    "payload": wireguardSignature['payload'],
    "signature": wireguardSignature['signature']
}
override_dns(wireguardServerInfo['server_name'], wireguardServerInfo['server_vip'])
# make a request to the WG server VIP and get our signature
wireguardPortResponse = requests.get(f"https://{wireguardServerInfo['server_name']}:19999/bindPort", params=createObject, verify=piaCA)
if wireguardPortResponse.status_code != 200:
    print("wireguardserver bindPort request failed non 200 status code - Trying to get port and keep port active")
    sys.exit(2)
wireguardPort = json.loads(wireguardPortResponse.text)
printDebug("PIA Port Request")
printDebug(wireguardPortResponse.text)

if wireguardPort['status'] != 'OK':
    if os.path.isfile(piaPortFile):
        os.remove(piaPortFile)
        printDebug("remove port file because status is no longer ok status returned")

# save required information to file for next time
wireguardSignature['refresh_epoch'] = currentEpoch
with open(portForwardSignatureFile, 'w') as filetowrite:
    filetowrite.write(json.dumps(wireguardSignature))
    printDebug(f"Saved wireguardSignature and payload to {portForwardSignatureFile}")

# check if the PIA port forward alias exists
opnsensePiaPortUpdated = False
piaPortAliasResponse = requests.get(f"{opnsenseURL}/api/firewall/alias/getAliasUUID/{opnsensePiaPortName}", auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
if r.status_code != 200:
    print("getAliasUUID request failed non 200 status code - Checking if the port forward alias exists")
    sys.exit(2)
piaPortAlias = json.loads(piaPortAliasResponse.text)
if piaPortAlias:
    opnsensePiaPortUUID = piaPortAlias['uuid']

# Now we know if its does or does not exist, we can create/update it
if opnsensePiaPortUUID == '':
    createObject = {
        "alias": {
            "enabled": '1',
            "name": opnsensePiaPortName,
            "description": "PIA Port forwarded, port from WireGuard PIA script",
            "type": "port",
            "content ": wireguardSignature['port']
            }
        }
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/firewall/alias/addItem/', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("addItem request failed non 200 status code - trying to create the pia port forward alias")
        sys.exit(2)
    opnsensePiaPortUpdated = True
else:
    # get current port alias information, so we can check its the right port
    piaPortAliasResponse = requests.get(f'{opnsenseURL}/api/firewall/alias/getItem/{opnsensePiaPortUUID}', auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
    if r.status_code != 200:
        print("getItem request failed non 200 status code - Checking if the port forward alias is set correctly")
        sys.exit(2)
    piaPortAlias = json.loads(piaPortAliasResponse.text)
    currentAliasPort = "0"
    for port in piaPortAlias['alias']['content']:
        if piaPortAlias['alias']['content'][port]['selected'] == 1:
            currentAliasPort = piaPortAlias['alias']['content'][port]['value']

    printDebug(f"CurrentPortInAlias: {str(currentAliasPort)}")
    printDebug(f"Required Port: {str(wireguardSignature['port'])}")
    if currentAliasPort != str(wireguardSignature['port']):
        printDebug("Ports don't match shall correct the Alias")
        piaPortAlias['alias']['content'] = wireguardSignature['port']
        piaPortAlias['alias']['type'] = 'port'
        piaPortAlias['alias']['counters'] = ''
        piaPortAlias['alias']['proto'] = ''
        piaPortAlias['alias']['interface'] = ''
        if 'categories' in piaPortAlias['alias'].keys(): 
            del piaPortAlias['alias']['categories']

        headers = {'content-type': 'application/json'}
        r = requests.post(f'{opnsenseURL}/api/firewall/alias/setItem/{opnsensePiaPortUUID}', data=json.dumps(piaPortAlias), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
        if r.status_code != 200:
            print("setItem request failed non 200 status code - trying to create the pia port forward alias")
            sys.exit(2)
        opnsensePiaPortUpdated = True
    else:
        printDebug("No port update required in OPNsense")

if opnsensePiaPortUpdated is False:
    sys.exit(0)

# Apply alias changes

createObject = {}
headers = {'content-type': 'application/json'}
r = requests.post(f'{opnsenseURL}/api/firewall/alias/reconfigure', data=json.dumps(createObject), headers=headers, auth=(config['opnsenseKey'], config['opnsenseSecret']), verify=urlVerify)
if r.status_code != 200:
    print("reconfigure request failed non 200 status code - apply alias changes")
    sys.exit(2)

#
# Script finished
#
sys.exit(0)

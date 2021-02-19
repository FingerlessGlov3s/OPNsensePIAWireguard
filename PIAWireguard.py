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

#
# User variables
#

opnsenseURL = "https://127.0.0.1" # connect to webui via local loopback, if you use a different port for webui add ":8443" for example
opnsenseKey = ""
opnsenseSecret = ""
opnsenseWGName = "PIA"
opnsenseWGPort = "51815"

piaUsername = ""
piaPassword = ""
piaRegionId = "uk" # https://serverlist.piaservers.net/vpninfo/servers/v4 id's can be found
piaPortForward = False # Only enable this if you know what you are doing

urlVerify = False # As we're connecting via local loopback I guess we don't really need to check the certificate. (I've noticed alot of people have the default self sigend anyway)

#
# end of User variables, do not edit anything after this point
#

#
# Script Start
#

opnsenseWGUUID = ""
opnsenseWGPubkey = ""
opnsenseWGIP = "192.0.0.2"
opnsenseWGGateway = "192.0.0.1"
opnsenseWGInstance = ""
opnsenseWGPeerName = f"{opnsenseWGName}-Server"
opnsenseWGPeerUUID = ""
opnsenseWGPeerSelected = False
opnsenseWGPeerPubkey = ""
opnsenseWGPeerPort = ""
opnsensePiaPortName = f"{opnsenseWGName}_Port"
opnsensePiaPortUUID = ""

piaServerList = 'https://serverlist.piaservers.net/vpninfo/servers/v4'
piaToken = ''
piaCA = '/conf/ca.rsa.4096.crt'
piaPort = ''
piaPortSignature = ''

serverChange = False
listRegions = False
debugMode = False

# Disable HTTPS verify warnings when Verify turned off
if urlVerify is False:
    urllib3.disable_warnings()
# Process any args added to the script
if len(sys.argv) > 1:
    for arg in sys.argv:
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

if opnsenseKey == '':
    print("Please define opnsenseKey variable with the correct value")
    sys.exit(0)

if opnsenseSecret == '':
    print("Please define opnsenseSecret variable with the correct value")
    sys.exit(0)

if piaUsername == '':
    print("Please define piaUsername variable with the correct value")
    sys.exit(0)

if piaPassword == '':
    print("Please define piaPassword variable with the correct value")
    sys.exit(0)

# List current wireguard instances looking for PIA one
r = requests.get(f'{opnsenseURL}/api/wireguard/server/searchServer/', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
if r.status_code != 200:
    print("searchServer request failed non 200 status code - listing wireguard instances")
    sys.exit(2)

wireguardInstances = json.loads(r.text)['rows']

for instance in wireguardInstances:
    if instance['name'] == opnsenseWGName:
        opnsenseWGUUID = instance['uuid']
        opnsenseWGPubkey = instance['pubkey'].replace("=\n\n\n", '=')
        break

# if the PIA WG instance doesn't exist we'll create it.
if opnsenseWGUUID == '':
    createObject = {
        "server": {
            "enabled": '1',
            "name": opnsenseWGName,
            "port": opnsenseWGPort,
            "tunneladdress": opnsenseWGIP,
            "disableroutes": '1',
            "gateway": opnsenseWGGateway,
            }
    }
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/addServer/', data=json.dumps(createObject), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("addServer request failed non 200 status code - trying to add wireGuard Instance")
        sys.exit(2)

    # get UUID of the PIA WG instance now its created
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/searchServer/', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("searchServer request failed non 200 status code - getting our PIA instance GUID")
        sys.exit(2)

    wireguardInstances = json.loads(r.text)

    for instance in wireguardInstances['rows']:
        if instance['name'] == opnsenseWGName:
            opnsenseWGUUID = instance['uuid']
            opnsenseWGPubkey = instance['pubkey'].replace("=\n\n\n", '=')
            break

# Get PIA WG instance information, so we can check if the PIA client (peer) has been added
r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{opnsenseWGUUID}', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.get(f'{opnsenseURL}/api/wireguard/client/searchClient/', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.post(f'{opnsenseURL}/api/wireguard/client/addClient/', data=json.dumps(createObject), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("addClient request failed non 200 status code - trying to add new wireGuard client (peer)")
        sys.exit(2)


# Now we know we have the WG client (peer) we needs its UUID and pubkey
r = requests.get(f'{opnsenseURL}/api/wireguard/client/searchClient/', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{opnsenseWGUUID}', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)

    if r.status_code != 200:
        print("getServer request failed non 200 status code - adding peer to server")
        sys.exit(2)

    wireguardInstanceInfo = json.loads(r.text)
    wireguardInstanceInfo['server']['peers'] = opnsenseWGPeerUUID
    wireguardInstanceInfo['server']['dns'] = ''
    wireguardInstanceInfo['server']['tunneladdress'] = opnsenseWGIP
    del wireguardInstanceInfo['server']['instance']

    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/setServer/{opnsenseWGUUID}', data=json.dumps(wireguardInstanceInfo), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
r = requests.get(f'{opnsenseURL}/api/wireguard/service/showhandshake/', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.get(piaServerList)
    if r.status_code != 200:
        print("Failed to get PIA server list, url is returning non 200 HTTP code, is there a connectivity issue?")
        sys.exit(2)
    serverList = json.loads(r.text.split('\n')[0])

    # Look for a pia server in the region we want.
    # PIA API will give us one server per region, PIA will try give us the best one
    wantedRegion = None
    for region in serverList['regions']:
        if region['id'] == piaRegionId:
            wantedRegion = region

    # couldn't find region, make sure the piaRegionId is set correctly
    if wantedRegion is None:
        print("region not found, correct piaRegionId set?")
        sys.exit(2)

    # print some useful debug information about what servers
    printDebug("metaServer")
    printDebug(wantedRegion['servers']['meta'])
    printDebug("wgServer")
    printDebug(wantedRegion['servers']['wg'])

    # Get token from wanted region server - Tokens lasts 24 hours, so we can make our requests for a WG connection information and port is required
    # because PIA use custom certs which just have a SAN of their name eg london401, we have to put a temporary dns override in, to make it so london401 points to the meta IP
    override_dns(wantedRegion['servers']['meta'][0]['cn'], wantedRegion['servers']['meta'][0]['ip'])
    generateTokenResponse = requests.get(f"https://{wantedRegion['servers']['meta'][0]['cn']}/authv3/generateToken", auth=(piaUsername, piaPassword), verify=piaCA)
    if generateTokenResponse.status_code != 200:
        print("wireguardserver generateToken request failed non 200 status code - Trying to get PIA token")
        sys.exit(2)
    piaToken = json.loads(generateTokenResponse.text)['token']

    createObject = {
        "pt": piaToken,
        "pubkey": opnsenseWGPubkey
    }

    printDebug("Your PIA Token, DO NOT GIVE THIS TO ANYONE")
    printDebug(generateTokenResponse.text)

    # Now we have out PIA token, we can now request our WG connection information
    # because PIA use custom certs which just have a SAN of their name eg london401, we have to put a temporary dns override in, to make it so london401 points to the wg IP
    override_dns(wantedRegion['servers']['wg'][0]['cn'], wantedRegion['servers']['wg'][0]['ip'])
    # Get PIA wireguard server connection information
    wireguardResponse = requests.get(f"https://{wantedRegion['servers']['wg'][0]['cn']}:1337/addKey", params=createObject, verify=piaCA)
    if wireguardResponse.status_code != 200:
        print("wireguardserver addKey request failed non 200 status code - Trying to add instance public key to server in exchnage for connection information")
        sys.exit(2)
    wireguardServerInfo = json.loads(wireguardResponse.text)
    printDebug("WG Server connection information")
    printDebug(wireguardResponse.text)


    # Write wireguard connection information to file, for later use.
    # we need to add server name as well
    wireguardServerInfo['server_name'] = wantedRegion['servers']['wg'][0]['cn']
    wireguardServerInfo['servermeta_ip'] = wantedRegion['servers']['meta'][0]['ip']
    wireguardServerInfoFile = f"/tmp/wg{opnsenseWGInstance}_piaserverinfo"
    with open(wireguardServerInfoFile, 'w') as filetowrite:
        filetowrite.write(json.dumps(wireguardServerInfo))
        printDebug(f"Saved wireguard server information to {wireguardServerInfoFile}")

    # update PIA WG instance with the new client side information
    # first we get the current settings for the WG instance
    r = requests.get(f'{opnsenseURL}/api/wireguard/server/getServer/{opnsenseWGUUID}', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("getServer request failed non 200 status code - adding peer to server")
        sys.exit(2)

    # Make our necessary changes
    wireguardInstanceInfo = json.loads(r.text)
    wireguardInstanceInfo['server']['enabled'] = '1'
    wireguardInstanceInfo['server']['peers'] = opnsenseWGPeerUUID
    wireguardInstanceInfo['server']['tunneladdress'] = wireguardServerInfo['peer_ip']
    wireguardInstanceInfo['server']['gateway'] = wireguardServerInfo['server_vip']
    wireguardInstanceInfo['server']['dns'] = ''
    del wireguardInstanceInfo['server']['instance'] # remove this as its not required in the request

    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/server/setServer/{opnsenseWGUUID}', data=json.dumps(wireguardInstanceInfo), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("setServer request failed non 200 status code - trying update WG instance to acquired PIA settings")
        sys.exit(2)

    # update PIA WG client (peer) instance, with the server side details
    r = requests.get(f'{opnsenseURL}/api/wireguard/client/getClient/{opnsenseWGPeerUUID}', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.post(f'{opnsenseURL}/api/wireguard/client/setClient/{opnsenseWGPeerUUID}', data=json.dumps(wireguardPeerInstanceInfo), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.post(f'{opnsenseURL}/api/wireguard/general/set', data=json.dumps(createObject), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("turn on wireguard request failed non 200 status code - trying to enable wireguard)")
        sys.exit(2)
    # Apply the wireguard saves (save button in the interface)
    createObject = {}
    headers = {'content-type': 'application/json'}
    r = requests.post(f'{opnsenseURL}/api/wireguard/service/reconfigure/{opnsenseWGPeerUUID}', data=json.dumps(createObject), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("reconfigure request failed non 200 status code - trying to apply all wireguard changes")
        sys.exit(2)

#
# Port forward section
# Note the tunnel must be up for the port forward requests to work, as they go over the tunnel
#

# If portforward isn't requied, exit script otherwise carry on
if piaPortForward is False:
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
        generateTokenResponse = requests.get(f"https://{wireguardServerInfo['server_name']}/authv3/generateToken", auth=(piaUsername, piaPassword), verify=piaCA)
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
piaPortAliasResponse = requests.get(f"{opnsenseURL}/api/firewall/alias/getAliasUUID/{opnsensePiaPortName}", auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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
    r = requests.post(f'{opnsenseURL}/api/firewall/alias/addItem/', data=json.dumps(createObject), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
    if r.status_code != 200:
        print("addItem request failed non 200 status code - trying to create the pia port forward alias")
        sys.exit(2)
    opnsensePiaPortUpdated = True
else:
    # get current port alias information, so we can check its the right port
    piaPortAliasResponse = requests.get(f'{opnsenseURL}/api/firewall/alias/getItem/{opnsensePiaPortUUID}', auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
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

        headers = {'content-type': 'application/json'}
        r = requests.post(f'{opnsenseURL}/api/firewall/alias/setItem/{opnsensePiaPortUUID}', data=json.dumps(piaPortAlias), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
        if r.status_code != 200:
            print("addItem request failed non 200 status code - trying to create the pia port forward alias")
            sys.exit(2)
        opnsensePiaPortUpdated = True
    else:
        printDebug("No port update required in OPNsense")

if opnsensePiaPortUpdated is False:
    sys.exit(0)

# Apply alias changes

createObject = {}
headers = {'content-type': 'application/json'}
r = requests.post(f'{opnsenseURL}/api/firewall/alias/reconfigure/{opnsenseWGPeerUUID}', data=json.dumps(createObject), headers=headers, auth=(opnsenseKey, opnsenseSecret), verify=urlVerify)
if r.status_code != 200:
    print("reconfigure request failed non 200 status code - apply alias changes")
    sys.exit(2)

#
# Script finished
#
sys.exit(0)

import json
import requests

piaServerList = 'https://serverlist.piaservers.net/vpninfo/servers/v6'

s = True
r = requests.get(piaServerList)
if r.status_code != 200:
    print("Failed to get PIA server list, url is returning non 200 HTTP code, is there a connectivity issue?")
    s = False
if s:
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
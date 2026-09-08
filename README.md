OPNsense PIA Wireguard Script
===
This script automates the process of setting up a Wireguard Point-To-Point VPN tunnel on OPNsense to connect to PIA's NextGen Wireguard servers.

It will create a Wireguard Instance and a Peer on your OPNsense deployment automatically.  It will then maintain the tunnel to keep it up and connected, with an automated check every 5 minutes.

You can also create a CRON job, allowing you to manually change the PIA server you are connected to.

**Warning: This is for Advanced Users**

**Prerequisites**
===
 1. OPNsense 25.7.11 or later
 1. WireGuard Plugin Installed
 1. HTTPS WebUI enabled 
    1. `System: Settings: Administration -> Web GUI`
    1. `Protocol: HTTPS`
 1. Secure Shell Access enabled (This can be reverted once the tunnel is working.)
    1. `System: Settings: Administration -> Secure Shell`
    1. `Enable Secure Shell`
    1. `Permit root user login`
    1. `Permit password login`
    
**Setup**
===
*If an older version of the script is already installed, jump to the Updating section*
 1. Create a new user called something on the lines of "WireguardAPI"
     1. Go to `System: Access: Users`
     1. Click the  `Plus` (Add) button on the bottom right of the users table
     1. Username: `WireguardAPI`
     1. Password:  leave empty
     1. Tick `Generate a scrambled password to prevent local database logins for this user.`
     1. Scroll down to you see `Privileges`, you want to give it the following permissions:
         - `Firewall: Alias: Edit`
         - `Firewall: Aliases`
         - `System: Static Routes`
         - `VPN: Wireguard`
     1. Click `Save`
     1. The new user `WireguardAPI` will now appear on the users list, on the command section of the table for that user, click `Create and download API key for this user` button which looks like a ticket. We'll leverage this later.
 1. SSH to OPNsense and drop in to a terminal via `option 8`.
 1. As `root`, run the below commands:
     - `fetch -o /conf https://raw.githubusercontent.com/FingerlessGlov3s/OPNsensePIAWireguard/main/PIAWireguard.py`
     - `fetch -o /conf https://raw.githubusercontent.com/FingerlessGlov3s/OPNsensePIAWireguard/main/ca.rsa.4096.crt`
     - `fetch -o /usr/local/opnsense/service/conf/actions.d https://raw.githubusercontent.com/FingerlessGlov3s/OPNsensePIAWireguard/main/actions_piawireguard.conf`
 1. Download the latest Release from GitHub to your computer, to ensure it's a stable release
    1. https://github.com/FingerlessGlov3s/OPNsensePIAWireguard/releases
 1. Edit the `PIAWireguard.json` file using Notepad++ or your favourite IDE.
    1. The following variables need to be filled in:
        - `opnsenseURL` Should only need to change this if you use a different `TCP Port` for the WebUI or changed the `Listen Interfaces`, the provided URL is correct if you've left those unchanged.
        - `opnsenseKey` WireguardAPI key you downloaded from step 2.2 `apikeys.txt`
        - `opnsenseSecret` WireguardAPI secret you downloaded from step 2.2  `apikeys.txt`
        - `piaUsername` Your PIA username
        - `piaPassword` Your PIA password
        - `instances` As we support creation of multiple tunnels, Example config has one instance but you can have as many as you like. The `instances` are key value pairs. Change `instancename` to something like `london` if you using the `uk` region since but the instance name can be what you'd like it to be.
        - `regionId` Change to your PIA region id (see below for details)
        - `opnsenseWGPort` outgoing port for OPNsense, this needs to be different for each tunnel and not already be in use for something else on OPNsense. Keep the double quotes around the number.
    1. These variables are already in the example config, set to a sensible default. Leave them as they are unless you want the feature:
        - `opnsenseWGPrefixName` Prefix used to name the objects the script creates in OPNsense: the WireGuard instance and peer become `pia-instancename` and `pia-instancename-server`, and the port forward alias becomes `pia_instancename_port`. Letters, numbers and underscores only. Only change this before your first run, changing it later will leave the previously created OPNsense objects behind.
        - `portForward` Enable port forwarding (note region support required)
        - `dip` and `dipToken` Only if you've purchased a PIA Dedicated IP (see [Dedicated IP](#dedicated-ip) below), otherwise leave as `false` and `""`.
    1. These variables are optional and deliberately not in the example config. Only add them if you want the feature, otherwise don't put them in the file at all:
        - `tunnelGateway` Only needed if you run multiple WANs and want the tunnel to go out of a specific one (see [Set outgoing tunnel gateway](#set-outgoing-tunnel-gateway-outgoing-interface) below).
        - `postConfigScript` Only needed if you want a script run after the tunnel is configured (see [Post configuration script](#post-configuration-script) below).
    1. Notes on the config file
        - The variables listed above are the complete set the script understands. Anything else is ignored, and the script will log a warning telling you the key was not recognised, so check the log if a setting doesn't seem to do anything.
        - **The `wg0` / `wg1` device number is not a config variable.** You assign it in the OPNsense WebUI later on in this guide, and the script works out which one belongs to each instance by itself. There is no `interface` setting.
    1. Region ID info
        - You can get your PIA region id by running `ListRegions.py` on your local device. 
        - If you don't have Python installed on your local device you can use this [Online Python Tool](https://trinket.io/embed/python3/5bfe65475964) 
            - Copy the contents of the file and then click `Run`. This will list the name and region id of each PIA region, for you choose from.
        - It is also possible to get PIA region ids running the main script using the argument `--listregions`
 1. Copy the `PIAWireguard.json` file to `/conf/` on your OPNsense router using SCP or Filezilla etc, make sure you using the root user of OPNsense when you connect, otherwise you'll get access denied messages.
     - Example `scp .\PIAWireguard.json root@192.168.1.1:/conf/PIAWireguard.json`
 1. SSH to OPNsense and drop in to a terminal `option 8`. (If you've closed the previous SSH connection.)
 1. Run the following commands
     - Enable the file to be executed:  `chmod +x /conf/PIAWireguard.py`
     - Restarted the service:  `service configd restart`
     - Execute the script, in debug mode with output:  `/conf/PIAWireguard.py --debug`
 1. Go to Interfaces: Assignments in OPNsense, so we can assign the new interface for the tunnel/tunnels
     1. At the bottom of the interfaces you'll see `New interface`, on the drop down select `wg0`, unless you already had one set up then select `wg1` etc...
     1. Give it a description like `WAN_PIAWG`
     1. Once selected click the `+` button
     1. A new `WAN_PIAWG_INSTANCENAME` interface will show on the list, which will be the new wg interface, click on it to edit.
     1. Tick `Enable Interface`, click save and Apply Changes. nothing else
 1. Go to `System: Gateways: Single`, so we can set up the PIA gateway for the tunnel/tunnels
     1. At the bottom right click the `+` button to add a new gateway
     1. Make sure `Disabled` is unchecked
     1. Enter the name `WAN_PIA_INSTANCENAME_IPv4`
     1. Interface select `WAN_PIAWG_INSTANCENAME`
     1. Tick `Far Gateway`
     1. Untick `Disable Gateway Monitoring`
     1. Click `Save and Apply Changes`
 1. Also reccomended you set your Main gateway to have a lower Priority number than the created ones for the PIA tunnel
 1. Go back to the SSH terminal, run the following command
     - `/conf/PIAWireguard.py --debug --changeserver instancename`
 1. Now OPNsense should be setup to use the PIA VPN tunnel as an internet gateway.  If you go back in to `System: Gateways: Single`, you should see `WAN_PIA_INSTANCENAME_IPv4` now has a gateway IP and is pinging
 1. Now we need to set up a cron job to make sure the tunnel says up, and changes server when necessary. Go to System: Settings: Cron
     1. Click the `plus` button at the bottom right of the table
     1. Enter `*/5` in the minute box
     1. Enter `*` in the hours box
     1. Select `PIA WireGuard Monitor Tunnels` on the command dropdown
     1. Give it a Description of your choice.
     1. Click Save
 1. Last thing we need to set up is maximum MSS for TCP packets, which is 40 bytes smaller than the MTU of WireGuard.  By default Wireguard uses 1420 bytes MTU. So we need to set an MSS maximum of 1380. (Without this you may have issues loading websites or slow speeds).
    1. Goto `Firewall: Settings: Normalization`
    1. Click `Add`
    1. Interface select `WAN_PIA_INSTANCENAME_IPv4`
    1. Enter Description of `Maximum MSS for PIA WireGuard Tunnel`
    1. Max MSS to `1380`
    1. Click `Save` (you will notice it'll now list this as OPT rather than the interface name, don't worry it's still correct, just edit it to verify you made the right selection)
    1. Click `Apply Changes`
 1. OPNsense should now look after the tunnel itself encase the tunnel disconnects, every 5 minutes it'll check the status and change server if the server has gone down.
 1. You'll need to create your own NAT and Firewall rules to use this tunnel, an advanced user should be able to do this.
     - There is now a [guide on OPNsense Docs](https://docs.opnsense.org/manual/how-tos/wireguard-selective-routing.html#step-7-create-an-alias-for-the-relevant-local-hosts-that-will-access-the-tunnel), which will help you here. Step 7 onwards.

*Note: If your having speed issues, you may need to change PIA server region or lower the default MTU from 1420, advanced users should understand how to do this.*

**Updating**
===
Since 2024/01/05 the script has gone a complete overhaul.  The major change is the script is now able to handle multiple instances of the tunnel.  IE you can establish connections to multiple regions.

The main impact, is that our InstanceName needs to be unique since we'll have multiple instances.
- `{instancename}` is replaced with the name for your specific instance in the config file, example `london` would be come `pia-london` for the WireGuard instance name. See *Example config* below.

Update Steps:
1. Delete the current cron entry.
1. Populate the new `PIAWireguard.json` based on your old config file
1. Upload new `PIAWireguard.py` and `PIAWireguard.json` file to `/conf/`
1. Upload new `actions_piawireguard.conf` file to `/usr/local/opnsense/service/conf/actions.d/`
1. Run `service configd restart` to refresh new actions file via SSH
1. There's a few bits in the WireGuard section in OPNsense you need to rename
    1. Rename current WG instance name to `pia-{instancename}` from `PIA`
    1. Rename current WG peer to `pia-{instancename}-server` from `PIA-Server`
1. If your using port forwarding rename the alias to `pia_{instancename}_port` from `PIA_Port` 
1. Ensure you applied all changes
1. Run the new script via SSH in debug mode and ensure it's working `python3 PIAWireguard.py --debug`, should return `instancename tunnel up - last handshake x seconds ago` as the last log entry
1. Then run again but this time forcing a it to change server `python3 PIAWireguard.py --debug --changeserver instancename`, to ensure all changes will apply and work.
1. If all is working correctly, then re-create the cron entry, see above for example as command name changed to `PIA WireGuard Monitor Tunnels`
1. Now double check all your configured routes and rules, ensure IP leaking isn't happening etc

See releases, starting from the version you have installed, to see if there's anything you need to do, usually it's just upgrade the py script itself. Release description will have the required commands, and notes for upgrading.

**Example Config**
===
Example config
```json
{
    "opnsenseURL": "https://127.0.0.1:443",
    "opnsenseKey": "/FQDXExojUWWuBdnPEPCUt98vnrQOdLxFqypTIEhE41304uYgA68ZJw7fveXBpXkMHqiAdx04cRAlLwh",
    "opnsenseSecret": "p+Gi4uE1xypuGIptbhrDylGKcNd9vaRpQ298eH0k6SFRQ6Crw4fLk0cIA0eSuKvWEN0hKx8JaIGUtNPq",
    "piaUsername": "p1234567",
    "piaPassword": "EncryptAllTheThings",
    "opnsenseWGPrefixName": "pia",
    "instances": {
        "london": {
            "regionId": "uk",
            "dipToken": "",
            "dip": false,
            "portForward": true,
            "opnsenseWGPort": "51815"
        }
    }
}
```

*Note: Passwords and keys in the example are not real*

**Arguments**
===
You may list the arguments you can pass in to the script by doing the following "/conf/PIAWireguard.py --help` an example output is below.
```
usage: PIAWireguard.py [-h] [--debug] [--listregions] [--changeserver [instancename]]

Python script to automate connections to PIA's WireGuard Servers. Source:
https://github.com/FingerlessGlov3s/OPNsensePIAWireguard

optional arguments:
  -h, --help            show this help message and exit
  --debug               Enable debug logging
  --listregions         List available regions and their properties
  --changeserver [instancename]
                        Change server for instance name or "all" for all instances
```

`--debug` shows debug logging, to see what the script is doing or maybe not doing \
`--listregions` lists all of the available PIA regions \
`--changeserver [instancename]` allows you to rotate/change the server your connected to for that instance. \

Example: `/conf/PIAWireguard.py --debug --changeserver instance2` will change the server that instance2 is connecting too and print all debug messages.

***Port Forwarding***
===
To use port forwarding Enable `portForward` variable in the json file for the intance from `false` to `true`. This will create an alias in your system called `pia_instancename_port`, which you can then use in your Port Forwarding rule. This alias will self update when required.
If you need a way to find out this port for an internal application, you can go to the following URL of your OPNsense to get the port, as its published publicly to devices that can reach the HTTPS port of OPNsense
https://opnsense.lan/wg0_port.txt

Note: Not all server locations support port forwarding. If you enable `portForward` for an instance in a region that doesn't support it, the script will log a warning and skip requesting a port for that instance, rather than making requests the PIA server will refuse. You can check which regions support it with `--listregions`.

***Dedicated IP***
===
If you have purchased a Dedicated IP from PIA. Add your DIP token to `dipToken` in the json file for the instance, then to enable the usage simply set `dip` to `true`. Remember PIA only give you the DIP token once, so make sure you have backed up the token somewhere.

I have developed this functionality by reserve engineering the PIA client, at this moment in time manual connections for DIP is not offically supported by PIA.

Note: I have not tested DIP in a while, so if this works for you let me know, if not create a GitHub issue.

***Set outgoing tunnel gateway (outgoing interface)***
===
In some deployments, people may be running dual or even triple WAN configurations, in this case due to how WireGuard is configured in FreeBSD (OPNsense), it'll route the PIA tunnel over the default WAN interface. Some people will want to change this to use another WAN interface as the gateway to route the PIA tunnel over.

To accommodate this functionality, this is built in to the script. You will need to get the name of your wanted gateway, for example `WAN2_DHCP`, then add a `tunnelGateway` variable to the json file with that name as its value (value needs to be in double quotes). When the script then runs it'll add/change a static route to enforce the PIA tunnel to use that gateway (interface).

```json
    "tunnelGateway": "WAN2_DHCP",
```

You'll find your gateway names in `System: Gateways: Single`, making sure its the IPv4 one.

**This must be one of your WAN gateways, not the PIA gateway.** The value names the gateway used to *reach* the PIA server, so the static route the script creates sends traffic for the PIA server IP out of that WAN. Do not put in the gateway you created for the PIA tunnel itself (the `WAN_PIA_INSTANCENAME_IPv4` one from the setup steps), that would try to route the PIA server through the very tunnel it's needed to build, and your tunnel won't come up.

If you have a single WAN you don't need this at all, so leave `tunnelGateway` out of your json file entirely and OPNsense will route the tunnel out of your default WAN. Older configs set it to `null` to mean the same thing, which still works, but leaving the variable out is the simpler option.

***Set VPN Kill Switch***
===
You will find that if the VPN tunnel isn't up, that traffic that should flow over it, will instead head straight out your WAN interface.  You can setup a "VPN Kill Switch" to prevent this.

1. `Firewall - Rules - WAN`
1. Create a new rule
    1. `Action - Block`
    1. `Quick - Apply the action immediately on match`
    1. `Interface - WAN`
    1. `Direction - Out`
    1. `Description - "Don't let traffic headed for VPN out the WAN"`
    1. `Match local tag = NO_WAN_EGRESS`
    1. Save this rule
    1. Repeat for other WAN interfaces, if you have a dual WAN setup, for most people this is not needed.
1. `Firewall - Rules - LAN` (Or whatever interface has VPN rules)
    1. Edit the rule where the gateway is the VPN tunnel
    1. Click `Advanced features Show/Hide`
    1. Under `Set local tag` add in `NO_WAN_EGRESS`
    1. Save this rule

***Post configuration script***
===
If you wish to run a custom script after a connection has been established to a new server or when the port forwarding port has changed, you can configure it to run any executable of your choice to perform additional actions.

For example, you could:
- Trigger a webhook to notify your monitoring system
- Update the peer port on your P2P client
- Restart or reload a service

To use this feature, add a `postConfigScript` key to your instance configuration in the `PIAWireguard.json` file. The value should be the full path to your custom script.

The script will be executed with:
- First argument is the instance name
- second argument forwarded port (only if port forwarding is enabled)

```
...
"london": {
    "regionId": "uk",
    "dipToken": "",
    "dip": false,
    "portForward": true,
    "opnsenseWGPort": "51815",
    "postConfigScript": "/conf/MyCustomScript.sh"
}
...
```

Example contents of your script to send the instance name and port as a webhook. Don't forget to set your script executable `chmod +x file`
```
#!/bin/sh
# This script sends the instance name and port to a webhook
curl -s -X POST https://webhook-test.com/af9ba6b577068f3284e31efd7dd64714 \
  -H "Content-Type: application/json" \
  -d "{\"instance\":\"$1\",\"port\":\"$2\"}"
```

---
`WireGuard` is a registered trademarks of Jason A. Donenfeld.

`Private Internet Access` is owned by Private Internet Access, Inc. All Rights Reserved

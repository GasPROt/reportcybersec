# Cybersecurity report - 2024

## NTLM Relay attacks

### Introduction
This report is about the NTLM relay attack. My work is based on the online tutorials
[SANS Workshop – NTLM Relaying 101](https://jfmaes-1.gitbook.io/ntlm-relaying-like-a-boss-get-da-before-lunch/) and [the 2022 NTLM guide on the companion site](https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022), with some modifications I will outline whenever the case.

The environment has been setup this way, under Virtual Box 7.0.14 r161095:

| Role | OS | IP |
|:------| :-----| :----|
| Domain controller   | Windows | 10.0.0.100 |
| File server SV01 | Windows | 10.0.0.10 |
| Victim client    | Windows | 10.0.0.2 |
| Attacker    | Ubuntu 22.04.01 LTS | 10.0.0.7 |

All Windows machines are Windows Server 2019 Standard Evaluation Version 10.0.17763 Build 17763 downloaded from the tutorial already setup for the lab (manual detailed configuration steps also provided in the SANS tutorial).

All network interfaces are setup as "internal network" and each machine has a static IP address inside the network 10.0.0.0/24. I made the following changes to the setup:
- changed the IP address of the victim from 10.0.0.1 to 10.0.0.2 due to conflict when using natted network during my experiments
- changed all the lockscreen and desktop background images for ease of presentation and screenshots
- configured a time synchronization method between VMs
- disabled energy savings
- issued slmgr -rearm to rearm the Windows Server evaluation version, which extends the evaluation period by 30 days to stop the annoying frequent automatic reboots.

### NTLM Relay
NTLM relay attacks are a powerful way to move around and escalate privileges in a domain network.
The attacker relays an incoming authentication request from a victim to a target service. 
When a server asks the client (attacker) to prove his identity by encrypting a challenge, the attacker passes that challenge on and asks a victim to encrypt that same challenge for himself in order to impersonate victim’s identity against the server.

The threat model assumes that the attacker has MITM at the TCP level capability, which is relatively simple to obtain in Windows environments, for example abusing DNS legacy fallback protocols like LLMNR and NBT-NS or leveraging IPv6 MITM.

Taken MiTM capability for granted, an attacker may then try to impersonate one of the two parties in execution of authentication protocol and even impersonate the client on a different server of his choice, as we will see in a moment.

Keep in mind that:
- many protocols are vulnerable to NTLM relay attack, such as SMB but also HTTP or LDAP, and attacks can also be carried “cross-protocol”;
- there is a matrix of compatibility of “cross-protocol” combinations with a very nice [diagram here](https://www.thehacker.recipes/ad/movement/ntlm/relay), according to which SMB can not be relayed to LDAP, but HTTP can (see also [this](https://en.hackndo.com/ntlm-relay/#what-can-be-relayed) )
- message signing, such as in SMB signing, prevents NTLM relay attacks, and this is why it is [becoming mandatory](https://www.techzine.eu/news/devops/107034/windows-11-makes-smb-signing-mandatory/)

So the basic building blocks of an NTLM relay attack are these:
- A target service that an attacker wants to access using the identity of the victim;
- Some relay tool that handles the message exchange in the relay protocol;
- A user (victim) connecting to the attacker: the victim will encrypt the challenge(s) on behalf of the attacker.

### Attack 0: Initial reconnaisance

We need to learn more about our network environment. 
First of all we can search for broadcast traffic in the environment, for example from DNS replacement protocols like Link Local Multicast Name Resolution (LLMNR) and NetBIOS Name Resolution (NBT-NS).

We can then use Responder in analyze mode as follows : 
```
sudo responder -I enp0s3 -A
```
The `-A` flag makes sure we are just listening and not actually poisoning anything. 
When I logged on the victim pc opened a file browser and tried to connect to `\\UGABUGA\`, the responder interface populated with lots of messages showing that LLMNR, NBT-NS and IPv6 are enabled on the network.


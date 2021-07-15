# pen-testing-1
Identify any vulnerabilities associated with the public-facing web application for fictional corporation "Altoro Mutual" and perform security tests against workstation belonging to CEO of fictional company "GoodCorp Inc."

# Altoro Mutual

## Summary
Altoro Mutual, a banking service, is concerned about their online presence and security of website `demo.testfire.net` being compromised by malicious actors. This report outlines the non-invasive investigation of their online security through website enumeration, discovery, and vulnerability detection. 

## Google Dorking
Using Google and its built-in search criteria, any person with access can easily discover the name of the CEO of Altoro Mutual: *Karl Fitzgerald*. 

Search terms used:
`site:demo.testfire.net "Chief Executive Officer"`

Using the name of the CEO, an attacker can attempt brute force attacks to access the website and other systems belonging to Altoro Mutual by attempting login credentials.

They can also spoof an email using his name and a similar email address to those automatically generated for employees to perform a social engineering campaign on other employees, or to target the CEO directly using his name through legitimate-looking emails.

## DNS and Domain Discovery
Using Domain Dossier, one can discover various details about Altoro Mutual and its internal network attached to the domain `demo.testfire.com`.

**Company Location**
Sunnyvale, CA

**NetRange IP Address**
65.61.137.64 - 65.61.137.127

**Infrastructure Storage**
Rackspace Backbone Engineering

**DNS Server IP Address**
65.61.137.117

## Shodan

Using Shodan, the notable details are revealed to be:
* open ports: 80 (TCP), 443 (TCP)
* running services: Apache Tomcat/Coyote JSP engine 1.1

## Recon-ng

Using Recon-ng, it is discovered that `demo.testfire.net` is vulnerable to XSS.

1. Install the Recon module `xssed`
  * `marketplace install xssed`
2. Set the source to `demo.testfire.net`
  * `options set SOURCE demo.testfire.net`
3. Run the module 
  * `run`

## Zenmap

Altoro Mutual has specifically requested a scan of any potential vulnerabilities with their file-sharing server.

After using Zenmap, it is apparent that under TMP, any anonymous user is able to read or write files in the C:\tmp directory. This leaves integrity and confidentiality of any files in the temporary directory especially vulnerable to an attack.

This vulnerability can be mitigated by restricting anonymous editing on files in this directory (or any others) by setting the DWORD value 'RestrictAnonymous' to 1 in the correct directory. This can also be mitigated by blocking NetBIOS on the host's Windows server by preventing TCP ports 139 and 445 from passing through the firewall on the network.

**Discovery Steps**

Use Zenmap to run a service scan against client machine and output results into a new text file named `zenmapscan.txt`:
* `nmap -sV 192.168.0.10 -oN 'scan-%T-%D.txt'`

Use Zenmap to execute a vulnerable script:
* `nmap -T4 -A -v --script smb-enum-shares 192.168.0.10`

# GoodCorp, Inc.

## Summary

GoodSecurity was tasked with performing an internal penetration test on GoodCorp’s CEO, Hans Gruber. An internal penetration test is a dedicated attack against internally connected systems. The goal of this test is to perform attacks similar to those of a hacker and attempt to infiltrate Hans’ computer to determine if it is at risk. GoodSecurity’s overall objective was to exploit any vulnerable software, find a secret recipe file on Hans’ computer, and report the findings back to GoodCorp.

The internal penetration test found several alarming vulnerabilities on Hans’ computer: When performing the attacks, GoodSecurity was able to gain access to his machine and find the secret recipe file by exploiting two programs with major vulnerabilities. The details of the attack are below.

## Findings

**Machine IP:**
192.168.0.20

**Hostname:**
MSEDGEWIN10

**Vulnerability Exploited:**
Icecast Header Overwrite

**Vulnerability Explanation:**
The Icecast Header Overwrite exploit exploits a buffer overflow in icecast’s header parsing. By sending 32 HTTP headers, the request writes one past the maximum pointer array, generally overwriting inconsequential files (readable not executable). Icecast thinks the thread is still in use through ExitThread, eventually maxing out the threadpool. ([Source](https://www.rapid7.com/db/modules/exploit/windows/http/icecast_header/))

**Severity:**
Because the vulnerability allows an attacker to execute arbitrary code on the victim’s host machine with Icecast server process privileges, this vulnerability should be classified as high severity.

## Proof of Concept

Perform a service and version scan using Nmap to determine which services are up and running.

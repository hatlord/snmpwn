SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against sites you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with "Unknown user name" when an SNMP user does not exist, allowing us to cycle through large lists of users to find the ones that do.

## **What does it do?**
- Checks that the hosts you provide are responding to SNMP requests.
- Enumerates SNMP users by testing each in the list you provide. Think user brute forcing.
- Attacks the server with the enumerated accounts and your list of passwords and encryption passwords. No need to attack the entire list of users, only live accounts.
- Attacks all the different protocol types:
	- No auth no encryption (noauth)
    - Authentication, no encryption (authnopriv)
    - Authentication and encryption (All types supported, MD5, SHA, DES, AES)
    
##  **Notes for usage**
Built for and tested on Kali Linux 2.x rolling. Should work on any Linux platform but does not work currently on Mac OSX (But will when I get around to it. This is due to the stdin and stdout messages for snmpwalk on OSX being different. This script basically wraps snmpwalk. The version of snmpwalk I used was 5.7.3.  
## **Install** 
gem install bundler
bundle install
Built for Ruby 2.3.x. Older versions of Ruby may work, but older than 1.9 may not. 
You may need to chmod u+x snmpwn before running.
## **Run**  
You need to provide the script a list of users, a hosts list, a password list and an encryption password list. Basic users.txt and passwords.txt files are included. You could use passwords.txt for your encryption list also. I would recommend generating one specific to the organisation you are pen testing.

> ./snmpwn.rb --hosts hosts.txt --users users.txt --passlist passwords.txt --enclist passwords.txt

## Screengrabs  

![User Enumeration]({{site.baseurl}}/https://cloud.githubusercontent.com/assets/5301488/16200880/0a9a54ea-3707-11e6-9d2c-a246276bf034.png)






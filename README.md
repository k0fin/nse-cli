# nse-cli

## About
-The nse-cli, or Nmap Scripting Engine Command Line Interface, is a tool written in Python2 to assist penetration testers by being able to
  quickly index, search, and execute NSE scripts for vulnerability scanning and enumeration.

## Dependencies
 -The following native Python2 modules are implemented in nse-cli:
   *sys
   *os
   *glob

 -The following 3rd party dependency is implemented in nse-cli:
   *python-nmap

## Usage
 -Some usage examples using the nse-cli are shown below:
   * ./nse-cli.py -h (print help menu)
   * ./nse-cli.py -l (list all local scripts)
   * ./nse-cli.py -s 468 -i (read info on script, referenced by script ID 468)
   * ./nse-cli.py -s ftp-anon -t localhost -p 21 (execute the ftp-anon script against localhost:21)
   * ./nse-cli.py -s 423 -t localhost -p 445 (execute the SMB share enumeration script against localhost:445 referenced by ID 423)

## Why
 -Because crawling around /usr/share/nmap/scripts kind of sucks.

## Todo
 - Automate target scanning and assign applicable scripts based on fingerprinted services.
 - Use NSE scan results to recommend Metasploit modules.
 - Along with supplying ports (e.x. specifically scanning service running on alternate/uncommon ports), detect ports to scan based on executed script.

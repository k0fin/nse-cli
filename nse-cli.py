#!/usr/bin/python2

import sys
import os
import glob
import nmap

from argparse import ArgumentParser

NSE_PATH = '/usr/share/nmap/scripts/'

def banner():
    os.system('clear')
    bfile = './banners/nse-cli.banner'
    with open(bfile,'r') as banner:
	buf = banner.read()
	if '=' in buf:
	    buf = buf.replace('=','\033[1;34m=\033[1;m')
	print buf

def enumFiles():
    global NSE_PATH

    file_list = []
    for file in glob.glob('{}*'.format(NSE_PATH)):
	file_list.append(file)
    return file_list

def scriptList(flist):
    id = 1
    for file in flist:
	filename = file.split('/')[5].split('.nse')[0].capitalize().strip()
	print '\033[1;34m[\033[1;m {} \033[1;34m]\033[1;m - {}'.format(id,filename)
	id += 1

def filePair(filelist):
    id = 1
    namepairs = {}
    for filepath in filelist:
	filename = filepath.split('/')[5].split('.nse')[0].strip()
        namepairs.update({id:{'path':filepath, 'name':filename}})
	id += 1
    return namepairs

def enumInfo(keys):
    global NSE_PATH

    masterkeys = {}

    for key in keys:
	if keys[key]['path'] == '{}{}'.format(NSE_PATH,'script.db'):
	    continue
	with open(keys[key]['path'],'r') as nsefile:
	    try:
	        list_obj = nsefile.read().split(']]')[0].split('[[')[1]
	    except IndexError:
		pass
	    masterkeys.update({key:{
				    'name': keys[key]['name'],
				    'path': keys[key]['path'],
				    'info': list_obj
				    }
				})
    return masterkeys

def scanTarget(s,t,p,debug=None):
    os.system('nmap -Pn -sT --script={} {} -p {} {}'.format(s,t,p,debug))

def matchScripts(target,service,version,name):
    files = enumInfo(filePair(enumFiles()))
    for id in files:
	name = files[id]['name']
	path = files[id]['path']
	info = files[id]['info']
	print name
	print path
	print info
        sys.exit()

def autoEnumerate(keys):
    for target in keys:
	tkeys = keys[target]
	for port in tkeys:
	    protocol = tkeys[port][0]
	    app_proto = tkeys[port][1]
	    service = tkeys[port][2]
	    version = tkeys[port][3]
	    state = tkeys[port][4]
	    tresponse = tkeys[port][5]
	    matchScripts(target,service,version,app_proto)

def updateScripts():
    print "\033[1;34m[<>]\033[1;m Updating local NSE scripts..."
    os.system('nmap --script-updatedb')
    print "\033[1;34m[<>]\033[1;m Local NSE scripts updated."

def nseCli():
    banner()

    parser = ArgumentParser()

    parser.add_argument('-d', '--debug', help='debug script execution', action="store_true")
    parser.add_argument('-f', '--find', help='look for nse script locally')
    parser.add_argument('-i', '--info', help='look up info for script by name or ID', action="store_true")
    parser.add_argument('-l', '--list', help='list all available nse scripts', action="store_true")
    parser.add_argument('-p', '--port', help='target port to scan')
    parser.add_argument('-r', '--range', help='list <r> amount of scripts')
    parser.add_argument('-s', '--script', help='script to use by name or ID')
    parser.add_argument('-t', '--target', help='target address to scan')
    parser.add_argument('-u', '--update', help='update NSE scripts', action="store_true")

    args = parser.parse_args()
    
    debug = args.debug
    find = args.find
    info = args.info
    list = args.list
    port = args.port
    range = args.range
    script = args.script
    target = args.target
    update = args.update

    if update:
	updateScripts()
	
    if not update and not find and not list and not script and not target:
	print '\033[1;34m=\033[1;m' * 80
	parser.print_help()
	print '\033[1;34m=\033[1;m' * 80
	sys.exit()

    if list:
	files = enumInfo(filePair(enumFiles()))
	print '\033[1;34m=\033[1;m' * 80
	print 'Search Results'
	print '\033[1;34m=\033[1;m' * 80
	for f in files:
	    print '\033[1;34m[\033[1;m {0:3} \033[1;34m]\033[1;m - {1:10}'.format(f,files[f]['name'])
	    if range:
		if int(range) == int(f):
		    break
	print '\033[1;34m=\033[1;m' * 80

    if find:
	files = enumInfo(filePair(enumFiles()))
	print '\033[1;34m=\033[1;m' * 80
	print 'Search Results'
	print '\033[1;34m=\033[1;m' * 80
	for f in files:
	    if find in files[f]['name'] or find.capitalize() in files[f]['name'] or find.lower() in files[f]['name']:
		print '\033[1;34m[\033[1;m {0:3} \033[1;34m]\033[1;m - {1:10}'.format(f,files[f]['name'])
	print '\033[1;34m=\033[1;m' * 80

    if script:
	index = enumInfo(filePair(enumFiles()))
	for i in index:
	    name = index[i]['name']
	    path = index[i]['path']
	    if script == name or script == str(i):
		print "\033[1;34m[<>]\033[1;m NSE:"
		print "    \033[1;34m-\033[1;mName: {}".format(name)
		print "    \033[1;34m-\033[1;mPath: {}".format(path)
		if info:
		    infokey = index[i]['info'].strip()
		    print "\n \033[1;34m_____________________\033[1;m"
		    print "\033[1;34m|\033[1;m Script Information  \033[1;34m|\033[1;m\n{}".format('\033[1;34m=\033[1;m' * 80)
		    print '\033[1;34m-> \033[1;m' + infokey
		    print '\033[1;34m=\033[1;m' * 80
	        if target:
	            print "    \033[1;34m-\033[1;mTarget: {}".format(target)
		    print "    \033[1;34m-\033[1;mPort  : {}".format(port)
	            if debug:
		        scanTarget(name,target,port,debug='-d')
		    else:
			scanTarget(name,target,port,debug=None)
                else:
		    pass
		    sys.exit(-1)
	    else:
		continue

nseCli()


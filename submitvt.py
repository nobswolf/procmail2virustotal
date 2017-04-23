#!/usr/bin/python 
 
# Filter for using VirusTotal VT as a ProcMail-Filter
# (C)2014 Emil Obermayr u@bnm.me

# Makes use of the API demo of VT
# https://www.virustotal.com/

# My code-blog
# https://plus.google.com/b/108361876263602371830/108361876263602371830/posts

import email
import json
import sys 
import os
import ConfigParser
import requests

### function "toCheck"
# check whether we should check the MIME-part
#
def toCheck (mimetype, filename) :
	global forceQuarantine
	checkit = True		# default: yes
	
	basename, ext = os.path.splitext(filename)	# split the suffix 
	fileext = ext.lower()								# make it lower-case for easy comparison
	
	if debug :
		print mimetype 
		print fileext
	
	if mimetype == "text/plain" :						# do not check simple text or HTML
		checkit = False 

        if mimetype == "application/pkcs7-signature" :                          # do not check simple text or HTML
                checkit = False

	if mimetype == "message/rfc822" :
                checkit = False

	if mimetype == "text/html" :						
		checkit = False 
		
	if fileext == ".exe" :								# do check if suffix is "scary"
		checkit = True	
		forceQuarantine = True

	if fileext == ".zip" :
		checkit = True	
                forceQuarantine = True

	if fileext == ".scr" :
		checkit = True	
                forceQuarantine = True

	if fileext == ".com" :
		checkit = True	
                forceQuarantine = True

	if fileext == ".pif" :
		checkit = True	
                forceQuarantine = True

        if fileext == ".wsf" :
                checkit = True
                forceQuarantine = True
	
	return checkit

###
# code starts here
#
dir = os.path.dirname (os.path.realpath(__file__))
config = ConfigParser.ConfigParser()
config.readfp(open(dir + '/checkvirus.cfg'))
apikey = config.get("main", 'apikey')				# VT-key to use; get it from your personal VT-page
debug = config.getboolean('main', 'debug')		# debugging switches off the remote checks
url = "https://www.virustotal.com/vtapi/v2/file/scan"	# URL to the VT-API

mailString = "".join(sys.stdin.readlines())		# get Mail as String vom Standard-In
msg = email.message_from_string (mailString)		# create the Email-Object
mailString = None											# forget the Email as String to save memory

for part in msg.walk() :								# iterate through all the MIME-parts
	link = "noinstance"
	pl = part.get_payload(decode=True)				# get the "body" of the MIME-part, use the decoding of base64 and such

	if isinstance(pl, str) :							# is there a real payload?
		mimetype = part.get_content_type()				# get the MIME-Type
		filename = part.get_filename ("none")		# get the filename
		link = filename

		if (toCheck(mimetype, filename)) :
			if debug :
				 link = "debug"
			else :
				params = {"apikey": apikey}			# define the parameters for the API-call
				files = {'file': (filename, pl)}
				response = requests.post(url, files=files, params=params)
				json = response.json()
				link = json["permalink"]

	msg["X-Virus-Link"] = link						
				
print msg.as_string(True)									# write changed message out

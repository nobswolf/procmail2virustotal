#!/usr/bin/python -W ignore::DeprecationWarning
# md5 is deprecated in 2.6 but ok in 2.7
 
# Filter for using VirusTotal VT as a ProcMail-Filter
# (C)2014 Emil Obermayr u@bnm.me

# Makes use of the API demo of VT
# https://www.virustotal.com/

# My code-blog
# https://plus.google.com/b/108361876263602371830/108361876263602371830/posts

import fileinput
import email
import md5
import json
import urllib
import urllib2
import sys
import os

### function "toCheck"
# check whether we should check the MIME-part
#
def toCheck (mimetype, filename) :
	checkit = True		# default: yes
	
	basename, ext = os.path.splitext(filename)	# split the suffix 
	fileext = ext.lower()								# make it lower-case for easy comparison
	
	if mimetype == "text/plain" :						# do not check simple text or HTML
		checkit = False 

	if mimetype == "text/html" :						
		checkit = False 
		
	if fileext == ".exe" :								# do check if suffix is "scary"
		checkit = True	

	if fileext == ".zip" :
		checkit = True	

	if fileext == ".scr" :
		checkit = True	

	if fileext == ".com" :
		checkit = True	

	if fileext == ".pif" :
		checkit = True	
	
	return checkit

###
# code starts here
#

# enter your VT API-key here
apikey = ""

debug = False												# debugging switches off the remote checks

mailstring = "" 											# collects the Mail as a String
url = "https://www.virustotal.com/vtapi/v2/file/report"	# URL to the VT-API
result = False												# defaults to a "negative"
resultStringLong = ""									# initialize String for verbose results

mailString = "".join(sys.stdin.readlines())		# get Mail as String vom Standard-In

msg = email.message_from_string (mailString)		# create the Email-Object

mailString = None											# forget the Email as String to save memory

for part in msg.walk() :								# iterate through all the MIME-parts
	pl = part.get_payload(decode=True)				# get the "body" of the MIME-part, use the decoding of base64 and such

	if isinstance(pl, str) :							# is there a real payload?
	
		mimetype = part.get_content_type()				# get the MIME-Type
		filename = part.get_filename ("none")			# get the filename
	
		if (toCheck(mimetype, filename)) :
			md5sum = md5.new(pl)							# create the md5-object of the payload
			md5sumString = md5sum.hexdigest()		# get the MD5sum of the payload
			parameters = {"resource": md5sumString, "apikey": apikey}	# define the parameters for the API-call
			data = urllib.urlencode(parameters)		# create the object of the parameters needed for the HTTP-call

			if debug :
				 jsonString = ""

			else :
				req = urllib2.Request(url, data)		# prepare the call
				response = urllib2.urlopen(req)		# do the call and get the response
				jsonString = response.read()			# get the response as a string

			if jsonString != "" :						# if not empty (will be empty if the API is overloaded)
				answer = json.loads(jsonString)		# decode the JSON
			
				if answer["response_code"] == 1 :	# if we got a regular result
					pos = answer["positives"]			# number of checks that consider this part as a virus
					tot = answer["total"]				# total number of checks
	
					if answer["positives"] != 0 :		# if there is any positive
						result = True						# set the result to malware
						resultStringLong += "# " + str(pos) + "/" + str(tot) + " "		# result 'en detail'
						
				else :
					resultStringLong += "# untested "	# no result, most likely that means: not a virus
	
			else :
				resultStringLong += "# no response "	# no response means nothing
		else :
			resultStringLong += "# not checked "	# "harmless" stuff not sent to VT 
if result :
	resultString = "Yes"									# prepare result for malware

else :
	resultString = "none found"						# result for "looks good so far"
				
msg["X-Virus-Flag"] = resultString					# set the short result, mainly used for procmail-filtering
msg["X-Virus-String"] = resultStringLong			# set long result

print msg.as_string()									# write changed message out

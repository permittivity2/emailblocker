#!/usr/bin/python3

######################################################################################################################################################
# Author:	Jeff Gardner
# Original Date:	November 21, 2021
#
# Description:
#	Takes as input mail from procmail and does a couple things:
#	1.	Adds a message at the top of the email with a link to a website for each eamil in the "To:" header
#			The website is responsible to handle flipping a value in the database to block the "To:" emails
#	2.	Adds the "To:" emails to a local sql database

import random
import re
import string 
import sys
import email
import quopri
import base64
import rsa
# from io import StringIO
# import io
try: 
    from BeautifulSoup import BeautifulSoup
except ImportError:
    from bs4 import BeautifulSoup

import mysql.connector

sys.path.append('/usr/local/lib/python3.8/local-packages')
# import giraffe


LOGDIR = "/home/gardner/.procmail/logs/"
stdin = []
msg = ""
BaseURL = 'https://blockthis.forge.name/blocker?blockthis='

def mydb(host=None, user=None, password=None, database=None):
	#	Description:	Creates a conn to a mysql database
	# 	Returns: 		mysql db connection object
    try:
        conn = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )
        return conn
    except:
        print(f'Unable to connect to {username=}@{host=} on database: {database=} with password: {password=}')
        return 1

def genRandStr(length=)1:
	# 	Description:	Generate a random, alpha-numeric string of a given length
	#	Returns:		a random string of a given length
	str = string.ascii_lowercase + string.ascii_uppercase + "1234567890"
	return ''.join(random.choice(str) for i in range(length))

def genRESTLink(emailAddress, BaseURL):
	# 	Description:	This needs to actually create a link on the web server or something but for now it just returns the email address and a REST URL
	#	Returns: tuple(emailaddrss, web link)
	randstr = genRandStr(12)
	endpoint = createWebServerCrap(emailAddress, randstr)
	RESTLink = BaseURL + endpoint
	restTuple = (emailAddress, RESTLink)
	return restTuple

# def rsaEncrypt(msg):
# 	# Most of this is shamelessly taken from https://stackoverflow.com/questions/65597453/how-to-store-private-and-public-key-into-pem-file-generated-by-rsa-module-of-pyt
# 	# Returns a tuple of (<encrypted string>, <public Key as Pkcs1 PEM>, <private Key as Pkcs 1PEM>)
# 	publicKey, privateKey = rsa.newkeys(1024)
# 	# Export public key in PKCS#1 format, PEM encoded 
# 	publicKeyPkcs1PEM = publicKey.save_pkcs1().decode('utf8') 
# 	print(publicKeyPkcs1PEM)

# 	# Export private key in PKCS#1 format, PEM encoded 
# 	privateKeyPkcs1PEM = privateKey.save_pkcs1().decode('utf8') 
# 	print(privateKeyPkcs1PEM)

# 	msgUTF8 = msg.encode('utf8')

# 	publicKeyReloaded = rsa.PublicKey.load_pkcs1(publicKeyPkcs1PEM.encode('utf8'))

# 	encrypted_msg = rsa.encrypt(plaintext, publicKeyReloaded)

# 	return ()


def createWebServerCrap(email, randomstring):
	#	Description:	This needs a major overhaul and does not really work!!!!
	#	What I want is to basically for this put info into a database that is used by PHP for a URL
		# The database has the email address (encrytpted), a random string to be matched,
		# and a column for block (basically true or false).
		# This Function will set the database entry (encrytped email address, random string, and block=false) and
		# will provide back an encoded values of the encrypted email address + random string.
		# That encoded string is attached to a URL that is picked up by a PHP script.
		# The PHPO script only does a few things:
		# 1. Decodes the URL and does a lookup ion the random string.
		# 2. If the random string exists then decrypt email and flip the value of the block column
		# 	If the random string does not exist then log a possible bad IP for further system analysis
	#	Returns:	Something... I don't know yet

    publickey, privatekey = rsa.newkeys(1024)
    encMessage = rsa.encrypt(email.encode(), privatekey)
    encodedB64_email = base64encode(str(encMessage), urlsafe=True)
    encodedB64_privatekey = base64encode(str(privatekey), urlsafe=True)

    conn = mydb(host="localhost", user="sendmail", password="mcl532", database="sendmail")
    # add_email = ("INSERT IGNORE INTO blockornot (email, string_id, block) VALUES (%s, %s, %s)")
    add_email = ("INSERT IGNORE INTO encblockornot (randomstring, email, privatekey, block, counter, lastactivets) VALUES (%s, %s, %s, %s, %s, now())")
    data_email = (randomstring, encodedB64_email, encodedB64_privatekey, 0, 0)

    cursor = conn.cursor()
    cursor.execute(add_email, data_email)
    conn.commit()
    conn.close()

    # Need to base64 encode the endpoint+publickey and return it
    encodedB64_publickey = base64encode(str(publickey), urlsafe=True)
    encodedB64_final = base64encode(f'{randomstring}+{encodedB64_publickey}', urlsafe=True)
    return encodedB64_final

def genEmailList(msgobj):
	# Description:	Generates a list of all email addresses in an email msgobj
	#					The msgobj needs to be of the "email" import module
	#					Take note that this onkly looks for "to" and "cc" filed (the values are made case insensitive)
	# Returns:	A list object with email addresses
	emailsToBlock = ""
	emailRegEx = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
	emailAddresses = []
	emailAddressesClean = []

	for (key, value) in msgobj.items():
		if (key.lower() == "to"):
			emailsToBlock = emailsToBlock + value
		if (key.lower() == "cc"):
			emailsToBlock = emailsToBlock + value
	emailsToBlock = re.sub(r"[\s\t\n\r ]+", "", emailsToBlock, flags=re.MULTILINE)
	emailAddresses = set(re.findall(emailRegEx, emailsToBlock))
	return emailAddresses

def genRESTLinkList(emailList):
	#	Description:	Generates a REST link for each email in a given list object
	#	Returns:	List object of rest links
	RESTLinksList = []
	
	for emailAddress in emailList:
		genRESTLinkTuple = genRESTLink(emailAddress, BaseURL)
		# print(f'genRESTLinkTuple: {genRESTLinkTuple}')
		RESTLinksList.append(genRESTLinkTuple)
	return RESTLinksList

def genNewPartText(payload, RESTLinks):
	#	Description: 	As part of an email body, there can be text parts and non-text parts
	#					This function adds a REST link to the top of a text part of an email
	#	Input:			"payload" is a text string
	#					"RESTLinks" is a list object of tuples
	#	Returns:		A string that has the REST links at the begining of the text
	payload = "\n********************************************************************************\n" + payload
	for RESTLink in RESTLinks:
		payload = f"********** Block {RESTLink[0]}: {RESTLink[1]} **********\n" + payload
		payload = "\n" + payload
	payload = "********************************************************************************\n\n" + payload
	return payload

def genNewPartHTML(payload, RESTLinks):
	#	Description: 	As part of an email body, there can be html parts (duh)
	#					This function adds a REST link to the top of an html part of an email
	#	Input:			"payload" is a text string
	#					"RESTLinks" is a list object of tuples
	#	Uses:			BeautifulSoup
	#	Returns:		A string that has the REST links at the begining of the text

	soup = BeautifulSoup(payload, 'html.parser')
	bodytag = soup.body

	for (email, link) in RESTLinks:
		#Create a new div tag
		blockemail_tag = soup.new_tag("div", style="border:5px solid black;padding:10px;margin:50px;")
		blockemail_tag.append("")

		#Add anchor tag for REST call to blockemail_tag
		blockemailanchor_tag = soup.new_tag("a", href=link, style="color:blue;")
		blockemailanchor_tag.append(f"Click or tap here to block {email}")
		blockemail_tag.insert(0, blockemailanchor_tag)
		
		if (bodytag == None):
			soup.insert(0, blockemail_tag)
		else:
			bodytag.insert(0, blockemail_tag)

	# return payload
	return str(soup.prettify())

def base64decode(encodedStr, urlsafe=False):
    # Shamelessly taken from https://www.base64decoder.io/python/
    if ( urlsafe ):
        decodedBytes = base64.urlsafe_b64decode(encodedStr)
    else:
        decodedBytes = base64.b64decode(encodedStr)
    decodedStr = str(decodedBytes, "utf-8")
    return decodedStr

def base64encode(data, urlsafe=False):
    # Shamelessly taken from https://www.base64decoder.io/python/
    if ( urlsafe ):
        encodedBytes = base64.urlsafe_b64encode(data.encode("utf-8"))
    else:
        encodedBytes = base64.b64encode(data.encode("utf-8"))
    encodedStr = str(encodedBytes, "utf-8")
    return encodedStr

def walkParts(msgobj, RESTLinks):
	# Description:	Walks through a message object (from mopdule email) and determins if a part is a worthy of adding
	#				an eamil blocker link
	#				As of writing this (November 2021), only text/plain and text/html seem to matter.
	#				This could change as different email types are determined
	# 				Note: when doing "part.set_payload()", this automagically sets it into the msgobj
	# Uses:			Module "email"
	# Returns:		A message object -- presumably to be of object "email"

	for part in msgobj.walk():
		contenttype = part.get_content_type()
		payload = part.get_payload()		
		if ("text/plain" in contenttype.lower()):
			contenttransferencoding = part.get('Content-Transfer-Encoding', failobj="").lower()
			if ( contenttransferencoding == 'base64' ):
				payload = base64decode(payload)
			payload = genNewPartText(payload, RESTLinks)
			if ( contenttransferencoding == 'base64' ):
				payload = base64encode(payload)
			part.set_payload(payload)
			# payload = genNewPartHTML(payload, RESTLinks)
		# Note: There is nothing saying an email can't be crapped up and have text/html and text/plain as the content header.
		#			This should NOT happen but it is also not preventable
		#		So, don't use an "else if"... just us an "if"
		if ("text/html" in contenttype.lower()):
			contenttransferencoding = part.get('Content-Transfer-Encoding', failobj="").lower()
			if ( contenttransferencoding == 'quoted-printable'):
				payload = quopri.decodestring(payload)
			if ( contenttransferencoding == 'base64' ):
				payload = base64decode(payload)
			payload = genNewPartHTML(payload, RESTLinks)
			if ( contenttransferencoding == 'base64' ):
				payload = base64encode(payload)
			part.set_payload(payload)
	return msgobj

if ( __name__ == "__main__" ):
	RESTLinks = []

	for line in sys.stdin:
		msg += line
	
	msgobj = email.message_from_string(msg)
	
	with open(f"{LOGDIR}/email.before.mod", "w") as f:
		f.write(msg)

	emailList = genEmailList(msgobj)
	RESTLinks = genRESTLinkList(emailList)

	# if msgobj.is_multipart():
	# 	for part in msgobj.walk():
	# 		part.make_mixed()

	# if msgobj.is_multipart() or True:
	# 	msgobj = walkParts(msgobj, RESTLinks)
	# else:
	# 	# Need to setup what to do if not multipart
	# 	pass

	msgobj = walkParts(msgobj, RESTLinks)

	as_string = msgobj.as_string()
	with open(f'{LOGDIR}/email.after.mod', 'w') as f:
		f.write(f'{as_string}')
	print(f'{as_string}')
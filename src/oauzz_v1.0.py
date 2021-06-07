from BaseHTTPServer import BaseHTTPRequestHandler
from Crypto.Hash import HMAC
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from getpass import getpass
from math import log10
from random import sample, randint
import sqlite3
import sys
from time import strftime, time
import urllib
import urllib2
from urlparse import urlparse


############################################################################################
### 
### TODO:
### 	* Aceptar otros medios ademas de la cabecera HTTP
### 	* Anadir informacion de COMENTARIO en la salida del FUZZING (igual que el original, no authorized...)
### 	* Anadir que en el unset de variables se pueda borrar, por ejemplo, la 3era cabecera HTTP (actualizar el show)
### 	* Plantilla HTML, arreglar Payloads muy largos
### 	* Meter en la BD la info del fuzzing
### 
############################################################################################


############################################################################################
############################################################################################
############################################################################################

############################################################################################
### HTTPClient
############################################################################################
class HTTPClient(object):
	"""This class implements several methods to interact with web servers."""

	####################################################################################
	# CONSTANTS
	####################################################################################
	
	### Body types
	
	# FORM_URLENCODED 
	BODY_FORM_URLENCODED = 10
	
	# OTHER
	BODY_OTHER = 11

	####################################################################################
	### ATTRIBUTES
	####################################################################################
	
	# Proxy handler
	__proxyHandler = None
	
	# The Opener
	__opener = None
	
	####################################################################################
	### METHODS
	####################################################################################
	
	####################################################################################
	@staticmethod
	def sendHTTPRequest (url, body=None, bodyType=BODY_FORM_URLENCODED, httpheaders=None, method="GET", proxy=None):
		'''Send a HTTP Request.
		@param url The URL.
		@param body The body params of the request.
		@param httpheaders The HTTP Headers of the request.
		@param method The HTTP Method.
		
		@return HTTP Response or the error.
		'''
		
		request = None
		if not httpheaders:
			httpheaders = {}
		
		if 'User-Agent' not in httpheaders.keys():
			httpheaders['User-Agent'] = 'OAuzz/%s' % Console.getVersion()
		
		# If there is parameters, they are encoded
		if body:
			bodystr = ""
			if bodyType == HTTPClient.BODY_FORM_URLENCODED:
				bodystr = urllib.urlencode(body)
			else:
				bodystr = body
			
			request = urllib2.Request ( url, bodystr, headers=httpheaders )
		else:
			request = urllib2.Request ( url, headers=httpheaders )
		
		# Select the HTTP method
		request.get_method = lambda: method
		
		# Define an opener if proxy is setted up
		opener = None
		if proxy:
			if proxy.lower().startswith('http://') and url.lower().startswith('https://'):
				proxy = 'https://' + proxy[7:]
			elif proxy.lower().startswith('https://') and url.lower().startswith('http://'):
				proxy = 'https://' + proxy[8:]
			proxyHandler = urllib2.ProxyHandler ( {request.get_type() : proxy} )
			opener = urllib2.build_opener ( proxyHandler )
		
		# Send the request
		try:
			if opener:
				response = opener.open (request)
			else:
				response = urllib2.urlopen (request)
		except urllib2.HTTPError, e:
			return (request, e)
		
		return (request, response)
	
	
	####################################################################################
	@staticmethod
	def getHeadersDict (httpheaders):
		"""Return a dictionary of HTTP Headers from a httpheaders list of strings."""
		
		httpheadersdict = {}
		
		if httpheaders:
			for h in httpheaders:
				if ':' in h:
					httpheadersdict[h.split(':')[0].strip()] = h.split(':')[1].strip()
		
		return httpheadersdict
	
	
	####################################################################################
	@staticmethod
	def getParametersDict (parameters):
		"""Return a dictionary of URL Parameters from a list of strings."""
		
		parametersdict = {}
		
		if parameters:
			parts = parameters.split('&')
			for p in parts:
				if '=' in p:
					parametersdict[p.split('=')[0]] = p.split('=')[1]
		
		return parametersdict
	
	
	####################################################################################
	@staticmethod
	def getURLEncodeForm1 (string):
		return string.replace ("-", "%2D").replace ("+", "%2B").replace ("|", "%7C").replace ("&", "%26")
	
	@staticmethod
	def getURLEncodeForm2 (string):
		return string.replace ("-", "%2D").replace ("+", "%2B").replace ("|", "%7C").replace ("&", "%26").replace ("=", "%3D").replace ("'", "%27").replace ('"', "%22")
	
	@staticmethod
	def getURLEncodeForm3 (string):
		return string.replace ("-", "%2D").replace ("+", "%2B").replace ("|", "%7C").replace ("&", "%26").replace ("=", "%3D").replace ("'", "%27").replace ('"', "%22").replace (' ', "%20")


############################################################################################
############################################################################################
############################################################################################

class DBHandler(object):
	"""This class implements several methods to work with the database results."""
	
	####################################################################################
	
	# Connection object to the database
	__connection = None
	
	# A cursor to operate with the database
	__cursor = None
	
	####################################################################################
	@staticmethod
	def openDB (dbname):
		"""This method opens/creates a instance of the database.
		
		@param dbname The name of the database."""
		
		# Open the database (or create the file if it doesn't exist).
		DBHandler.__connection = sqlite3.connect(dbname)
		
		# Set up a text factory to ignore unicode characters
		DBHandler.__connection.text_factory = lambda x: unicode(x, "utf-8", "ignore")
		
		# Open a cursor to operate with the database
		DBHandler.__cursor = DBHandler.__connection.cursor()
	
	
	####################################################################################
	@staticmethod
	def __createDB ():
		"""This method creates the structure of the database."""
		
		DBHandler.__cursor.execute('''CREATE TABLE RESULTS (
			variable text,
			originalValue text,
			responseCode integer,
			responseMessage text,
			responseLength integer,
			payload text,
			request text,
			response text
			)''')
		
		DBHandler.__connection.commit()
	
	
	####################################################################################
	@staticmethod
	def closeDB ():
		"""This method closes the opened instance of the database."""
		
		if DBHandler.__connection:
			DBHandler.__connection.close()
			DBHandler.__connection = None
		
		if DBHandler.__cursor:
			DBHandler.__cursor = None
	
	####################################################################################
	@staticmethod
	def isOpened ():
		"""This method check if the database is opened.
		
		@return True or False."""
		
		return DBHandler.__connection and True or False
	
	
	####################################################################################
	@staticmethod
	def insert (rows):
		"""This method insert a set of rows in the database.
		
		@param rows List of rows."""
		
		# Try to insert the rows in the database
		try:
			DBHandler.__cursor.executemany('''INSERT INTO RESULTS VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', rows)
			DBHandler.__connection.commit()
			return
		
		# If it cannot, maybe it is because the table doesn't exist:
		except sqlite3.OperationalError, e:
			DBHandler.__createDB ()
		
		# The first time, the rows weren't inserted, so after DB creation they are inserted.
		DBHandler.__cursor.executemany('''INSERT INTO RESULTS VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', rows)
		DBHandler.__connection.commit()
	
	####################################################################################
	@staticmethod
	def select (variable=None, originalValue=None, responseCode=None, responseMessage=None, 
		responseLength=None, payload=None, request=None, response=None):
		"""This method select rows from the database from the specified constraints.
		
		@params The different columns of the table.
		@returns A list with the results of the query."""
		
		query = 'SELECT * FROM RESULTS'
		constraints = []
		
		# There is some constraint
		if variable or originalValue or responseCode or responseMessage or responseLength or payload or request or response:
			
			first = True
			if variable:
				query += (first and '' or ' and ') + 'variable like ?'
				constraints.append ( '%' + variable + '%' )
			if originalValue:
				query += (first and '' or ' and ') + 'originalValue like ?'
				constraints.append ( '%' + originalValue + '%' )
			if responseCode:
				query += (first and '' or ' and ') + 'responseCode=?'
				constraints.append (responseCode)
			if responseMessage:
				query += (first and '' or ' and ') + 'responseMessage like ?'
				constraints.append ( '%' + responseMessage + '%' )
			if responseLength:
				query += (first and '' or ' and ') + 'responseLength=?'
				constraints.append (responseLength)
			if payload:
				query += (first and '' or ' and ') + 'payload like ?'
				constraints.append ( '%' + payload + '%' )
			if request:
				query += (first and '' or ' and ') + 'request like ?'
				constraints.append ( '%' + request + '%' )
			if response:
				query += (first and '' or ' and ') + 'response like ?'
				constraints.append ( '%' + response + '%' )
		
		# Execute the query
		if constraints:
			return DBHandler.__cursor.execute (query, tuple(constraints) ).fetchall()
		else:
			return DBHandler.__cursor.execute (query).fetchall()
	
	
	####################################################################################
	@staticmethod
	def directSelect (query):
		"""This method select rows from the database using the SQL SELECT statement.
		
		@params query An SQL SELECT statement.
		
		@returns A list with the results of the query."""
		
		sqlerror = "Incorrect SQL statement. The basic structure is:\n\nSELECT _usual_SQL_syntax_ FROM RESULTS [WHERE _expression_]\n\nExample: SELECT request FROM RESULTS WHERE responseCode=200\nType 'help select' to get more help."
		
		parts = query.split()
		parts = [p.upper() for p in parts]
		
		# Validate the SQL statement
		idxfrom = 0
		if 'FROM' in parts: 
			idxfrom = parts.index('FROM')
			if idxfrom:
				if parts[idxfrom+1] != 'RESULTS' or (len(parts) > idxfrom+2 and parts[idxfrom+2] != 'WHERE'):
					raise Exception(sqlerror)
		else:
			raise Exception(sqlerror)
		
		try:
			rows = DBHandler.__cursor.execute (query).fetchall()
		except:
			raise sqlite3.DatabaseError("It is NOT possible to read data from the database. Maybe the database file doesn't have the correct structure.")
		
		return rows



############################################################################################
############################################################################################
############################################################################################

class OAuth(object):
	"""
	Copyright (C) 2012 Julio Gomez Ortega

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
	----------------------------------------------------------------------------------
	
	This class implements several methods to perform OAuth signed request based on 
	RFC 5849:
		http://tools.ietf.org/html/rfc5849
	
	This is a basic implementation and it doesn't perform "automatic" steps like 
	OAuth authorization because it does not implement any HTTP method.
	
	Instead of that, the developer has to call the different methods to get nonces or
	timestamps, to calculate the signature... and use another library to perform
	the final HTTP Request.
	
	To contact with the author, you can write to:
	
		julgoor , which is a e-mail address of gmail/com 
	
	"""
	
	####################################################################################
	# CONSTANTS
	####################################################################################
	
	### Signature methods
	
	# Plaintext signature method
	PLAINTEXT = "PLAINTEXT"
	
	# Plaintext signature method
	HMAC_SHA1 = "HMAC-SHA1"
	
	# Plaintext signature method
	RSA_SHA1 = "RSA-SHA1"
	
	### Body types
	
	# FORM_URLENCODED 
	BODY_FORM_URLENCODED = 10
	
	# OTHER
	BODY_OTHER = 11
	
	
	####################################################################################
	# METHODS
	####################################################################################
	
	
	####################################################################################
	@staticmethod
	def generateNonce (l=42):
		"""This method returns a random alpha-numeric string with defined length.
		
		@param l Length of the returned string (must be greater than 0).
		@return A random l-length string."""
		
		charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
		return "".join(sample ( list(charset), (l<1 and 42 or l) ))
	
	
	####################################################################################
	@staticmethod
	def getTimestamp ():
		"""This methods returns the current timestamp of the system.
		
		@return Unix time."""
		
		return str(time()).split('.')[0]
	
	
	####################################################################################
	@staticmethod
	def getBodyHash (body):
		"""This methods calculates the SHA-1 of the body.
		
		@param body The body of the request.
		@return The base64 encoded form of the SHA-1 of the body."""
		
		return SHA.new(body).digest().encode('base64').strip()

	
	####################################################################################
	@staticmethod
	def __percentEncoding (string):
		"""This method encode an input string as defined in RFC 5849 Section 3.6, Percent Encoding:
		1.  Text values are first encoded as UTF-8 octets
		2.  The values are then escaped using the [RFC3986] percent-encoding (%XX)
			* ALPHA, DIGIT, "-", ".", "_", "~" MUST NOT be encoded. 
			* All other characters MUST be encoded.
			* The two hexadecimal characters used MUST be uppercase.
		
		@param string String to encode.
		@return Encoded string."""
		
		return urllib.quote(string.encode ('utf8'), '~')
	
	
	####################################################################################
	@staticmethod
	def __percentDecoding (string):
		"""This method decode an input string as defined in RFC 5849 Section 3.6, Percent Encoding.
		
		@param string String to decode.
		@return Decoded string."""
		
		return urllib.unquote(string)
		
	
	####################################################################################
	@staticmethod
	def __loadCertificate (certPath):
		"""This method load the content of a certificate file.
		
		@param certPath Path to the file with the certificate.
		
		@return The conent of the file."""
		
		content = None
		try:
			fcert = open(certPath)
			content = fcert.read()
			fcert.close()
			
		except:
			raise Exception("Something was wrong while trying to read certificate file.")
		
		return content
		
	
	####################################################################################
	@staticmethod
	def __getBasestring (url, method, consumerKey, nonce, timestamp, tokenKey=None, signatureMethod=HMAC_SHA1, version="1.0", oauthExtraParams=None, urlParams=None, body=None, bodyType=BODY_FORM_URLENCODED, bodyHash=False):
		"""This method generates de base string to be signed.
		
		@param url URL (without parameters)
		@param method HTTP Method
		@param consumerKey Consumer Key
		@param nonce Nonce of the request
		@param timestamp Timestamp of the request
		@param tokenKey Access or Request Key
		@param signatureMethod OAuth Signature Method
		@param version OAuth Version
		@param oauthExtraParams Parameters which have to be included in the Authorization Header
		@param urlParams Parameters in the URL (GET Method)
		@param body Parameters in the body of the request (POST)
		@param bodyType Type of body (FORM-URLENCODED by default)
		@param bodyHash Flag which indicates if the bodyhash must be calculated.
		
		@return OAuth base string.
		"""
		
		
		baseString = method.upper() + "&" + urllib.urlencode({url:""})[:-1] + "&"
		
		allparamas = {  "oauth_consumer_key" : consumerKey,
				"oauth_nonce" : nonce,
				"oauth_signature_method" : signatureMethod,
				"oauth_timestamp" : timestamp,
				"oauth_version" : version }
		
		# Check if the tokenKey must be included
		if tokenKey:
			allparamas['oauth_token'] = tokenKey
		
		# Check if the bodyHash must be included
		if bodyHash and 'oauth_body_hash' not in oauthExtraParams and bodyType != OAuth.BODY_FORM_URLENCODED and method != 'GET' and method != 'HEAD':
			bodyhash = 'oauth_body_hash=%s' % (OAuth.getBodyHash (body))
			if oauthExtraParams:
				oauthExtraParams += '&' + bodyhash
			else:
				oauthExtraParams = bodyhash
		
		# Check if the oauthExtraParams must be included
		if oauthExtraParams and '=' in oauthExtraParams:
			parts = oauthExtraParams.split('&')
			for p in parts:
				allparamas[p.split('=')[0]] = '='.join(p.split('=')[1:])
		
		# Check if the urlParams must be included
		if urlParams and '=' in urlParams:
			parts = urlParams.split('&')
			for p in parts:
				allparamas[p.split('=')[0]] = p.split('=')[1]

		# Check if the body must be included
		if body and bodyType == OAuth.BODY_FORM_URLENCODED and '=' in body:
			parts = body.split('&')
			for p in parts:
				allparamas[p.split('=')[0]] = p.split('=')[1]

		# Se ordenan
		order = allparamas.keys()
		order.sort()
		
		# Se unen todos
		temp = []
		for key in order:
			temp.append( OAuth.__percentEncoding(key) + '=' + OAuth.__percentEncoding(allparamas[key]) )
		
		baseparams = '&'.join(temp)
		
		# Se codifican en Percent Encoding todos los parametros
		baseString = baseString + OAuth.__percentEncoding(baseparams)
		
		return baseString
	
	####################################################################################
	@staticmethod
	def __getKey (consumerSecret, tokenSecret):
		"""This method return the key which will be used in signature calculation.
		
		@param consumerSecret Consumer Key.
		@param tokenSecret Access or Request Secret
		
		@return Signature key."""
		
		return OAuth.__percentEncoding(consumerSecret) + '&' + OAuth.__percentEncoding(tokenSecret)
	
	####################################################################################
	@staticmethod
	def signRequest (url, method, consumerKey, consumerSecret, tokenKey='', tokenSecret='', signatureMethod=HMAC_SHA1, nonce='', timestamp='', version="1.0", oauthExtraParams='', urlParams='', body='', bodyType=BODY_FORM_URLENCODED, bodyHash=False, certPath=None, passphrase=None):
		"""Signs a request and return the signature.
		
		@param url URL (without parameters)
		@param method HTTP Method
		@param consumerKey Consumer Key
		@param consumerSecret ConsumerSecret
		@param tokenKey Access or Request Key
		@param tokenSecret Access or Request Secret
		@param signatureMethod OAuth Signature Method
		@param nonce Nonce of the request
		@param timestamp Timestamp of the request
		@param version OAuth Version
		@param oauthExtraParams Parameters which have to be included in the Authorization Header
		@param urlParams Parameters in the URL (GET Method)
		@param body Parameters in the body of the request (POST)
		@param bodyType Type of body (FORM-URLENCODED by default)
		@param bodyHash Flag which indicates if the bodyhash must be calculated.
		@param certPath Path to the private key
		@param passphrase Private key's passphrase
		
		@return Base64 encoded signature
		"""
		
		# The final signature value will be updated in this variable
		signature = ""
		
		# PLAINTEXT signature
		if signatureMethod == OAuth.PLAINTEXT:
			
			signature = OAuth.signRequestPLAINTEXT (consumerSecret, tokenSecret)
		
		# HMAC-SHA1 signature
		if signatureMethod == OAuth.HMAC_SHA1:
			
			signature = OAuth.signRequestHMAC_SHA1 (url=url, method=method, consumerKey=consumerKey, 
				consumerSecret=consumerSecret, tokenKey=tokenKey, tokenSecret=tokenSecret, 
				nonce=nonce, timestamp=timestamp, version=version, oauthExtraParams=oauthExtraParams, 
				urlParams=urlParams, body=body, bodyType=bodyType, bodyHash=bodyHash)
		
		# RSA-SHA1 signature
		if signatureMethod == OAuth.RSA_SHA1 and certPath:
			
			signature = OAuth.signRequestRSA_SHA1 (url=url, method=method, consumerKey=consumerKey, 
				certPath=certPath, passphrase=passphrase, tokenKey=tokenKey, nonce=nonce, timestamp=timestamp, 
				version=version, oauthExtraParams=oauthExtraParams, urlParams=urlParams, body=body, 
				bodyType=bodyType, bodyHash=bodyHash)
			
		
		return signature
	
	
	####################################################################################
	@staticmethod
	def signRequestPLAINTEXT (consumerSecret, tokenSecret):
		"""Returns the PLAINTEXT signature.
		
		@param consumerSecret ConsumerSecret
		@param tokenSecret Access or Request Secret
		
		@return The signature value."""
		
		return OAuth.__getKey(consumerSecret, tokenSecret)
		
	
	
	####################################################################################
	@staticmethod
	def signRequestHMAC_SHA1 (url, method, consumerKey, consumerSecret, tokenKey='', tokenSecret='', nonce='', timestamp='', version="1.0", oauthExtraParams='', urlParams='', body='', bodyType=BODY_FORM_URLENCODED, bodyHash=False):
		"""Signs a request and return the HMAC-SHA1 signature.
		
		@param url URL (without parameters)
		@param method HTTP Method
		@param consumerKey Consumer Key
		@param consumerSecret ConsumerSecret
		@param tokenKey Access or Request Key
		@param tokenSecret Access or Request Secret
		@param nonce Nonce of the request
		@param timestamp Timestamp of the request
		@param version OAuth Version
		@param oauthExtraParams Parameters which have to be included in the Authorization Header
		@param urlParams Parameters in the URL (GET Method)
		@param body Parameters in the body of the request (POST)
		@param bodyType Type of body (FORM-URLENCODED by default)
		@param bodyHash Flag which indicates if the bodyhash must be calculated.
		
		@return Base64 encoded signature
		"""
		
		# Generate the base string
		baseString = OAuth.__getBasestring (
			url=url, 
			method=method, 
			consumerKey=consumerKey, 
			tokenKey=tokenKey, 
			nonce=nonce, 
			timestamp=timestamp, 
			signatureMethod=OAuth.HMAC_SHA1, 
			version=version, 
			oauthExtraParams=oauthExtraParams, 
			urlParams=urlParams, 
			body=body,
			bodyType=bodyType,
			bodyHash=bodyHash)
		
		# Generate the key
		key = OAuth.__getKey (consumerSecret, tokenSecret)
		
		# Sign the baseString with the key
		return HMAC.new(key, baseString, digestmod=SHA).digest().encode('base64').strip()
	
	
	####################################################################################
	@staticmethod
	def signRequestRSA_SHA1 (url, method, consumerKey, certPath, passphrase=None, tokenKey='', nonce='', timestamp='', version="1.0", oauthExtraParams='', urlParams='', body='', bodyType=BODY_FORM_URLENCODED, bodyHash=False):
		"""Signs a request and return the RSA_SHA1 signature.
		
		@param url URL (without parameters)
		@param method HTTP Method
		@param consumerKey Consumer Key
		@param certPath Path to the private key
		@param passphrase Private key's passphrase
		@param tokenKey Access or Request Key
		@param nonce Nonce of the request
		@param timestamp Timestamp of the request
		@param version OAuth Version
		@param oauthExtraParams Parameters which have to be included in the Authorization Header
		@param urlParams Parameters in the URL (GET Method)
		@param body Parameters in the body of the request (POST)
		@param bodyType Type of body (FORM-URLENCODED by default)
		@param bodyHash Flag which indicates if the bodyhash must be calculated.
		
		@return Base64 encoded signature
		"""
		
		# Load the private key to sign the request
		cert = OAuth.__loadCertificate (certPath)
		try:
			key = RSA.importKey(cert, passphrase)
		except:
			raise Exception ("The certificate format is not supported (use .pem files) or the passphrase is NOT correct.")
		p = PKCS1_v1_5.new(key)
		
		# Generate the base string
		baseString = OAuth.__getBasestring (
			url=url, 
			method=method, 
			consumerKey=consumerKey, 
			tokenKey=tokenKey, 
			nonce=nonce, 
			timestamp=timestamp, 
			signatureMethod=OAuth.RSA_SHA1, 
			version=version, 
			oauthExtraParams=oauthExtraParams, 
			urlParams=urlParams, 
			body=body,
			bodyType=bodyType,
			bodyHash=bodyHash)
		
		# Calculate the SHA1
		h = SHA.new(baseString)
		
		# Sign the SHA1 with the key and return the value
		return ''.join(p.sign(h).encode('base64').split('\n'))
	
	
	####################################################################################
	@staticmethod
	def extractTokens (response):
		"""From a getRequestToken response, this method extracts token key and secret.
		
		@param response The Content of a HTTP Response.
		@return A tuple with the token key and secret."""
		
		tokenKey = ""
		tokenSecret = ""
		if response:
			parts = response.split('&')
			for p in parts:
				if p.split('=')[0] == 'oauth_token':
					tokenKey = p.split('=')[1]
				elif p.split('=')[0] == 'oauth_token_secret':
					tokenSecret = p.split('=')[1]
		
		return (OAuth.__percentDecoding (tokenKey), OAuth.__percentDecoding (tokenSecret))
	
	####################################################################################
	@staticmethod
	def getAuthorizationHeader (signature, consumerKey, tokenKey="", signatureMethod=HMAC_SHA1, nonce="", timestamp="", version="1.0", oauthExtraParams="", realm=""):
		"""Compose a Authorization HTTP Header with all the parameters.
		
		@param signature OAuth Signature
		@param consumerKey Consumer Key
		@param tokenKey Access or Request Key
		@param signatureMethod OAuth Signature Method
		@param nonce Nonce of the request
		@param timestamp Timestamp of the request
		@param version OAuth Version
		@param oauthExtraParams Parameters which have to be included in the Authorization Header
		
		@return A string with the value of the HTTP Header."""
		
		# Create the HTTP Header
		authHeader = 'OAuth '
		
		if realm:
			authHeader += 'realm="%s", ' % realm
		
		authHeader += 'oauth_consumer_key="%s"' % OAuth.__percentEncoding(consumerKey)
		
		if nonce:
			authHeader += ', oauth_nonce="%s"' % OAuth.__percentEncoding(nonce)
		
		if timestamp:
			authHeader += ', oauth_timestamp="%s"' % OAuth.__percentEncoding(timestamp)
		
		if tokenKey:
			authHeader += ', oauth_token="%s"' % OAuth.__percentEncoding(tokenKey)
		
		if oauthExtraParams:
			parts = oauthExtraParams.split('&')
			for p in parts:
				if '=' in p:
					authHeader += ', %s="%s"' % ( OAuth.__percentEncoding(p.split('=')[0]), OAuth.__percentEncoding('='.join(p.split('=')[1:])) )
		
		authHeader += ', oauth_signature_method="%s", oauth_signature="%s", oauth_version="%s"' % (OAuth.__percentEncoding(signatureMethod), OAuth.__percentEncoding(signature), OAuth.__percentEncoding(version))

		return authHeader
		
	
	####################################################################################
	@staticmethod
	def getAuthorizationParameters (signature, consumerKey, tokenKey="", signatureMethod=HMAC_SHA1, nonce="", timestamp="", version="1.0", oauthExtraParams=""):
		"""Compose the set of OAuth parameters to be used in the URL or POST body.
		
		@param signature OAuth Signature
		@param consumerKey Consumer Key
		@param tokenKey Access or Request Key
		@param signatureMethod OAuth Signature Method
		@param nonce Nonce of the request
		@param timestamp Timestamp of the request
		@param version OAuth Version
		@param oauthExtraParams Parameters which have to be included in the Authorization Header
		
		@return A dictionary with (parameter_name : parameter_value) as values."""
	
		# Group the Parameters
		authorization = {
			'oauth_consumer_key' : consumerKey,
			'oauth_signature' : signature,
			'oauth_signature_method' : signatureMethod,
			'oauth_version' : version
			}
		
		if nonce:
			authorization['oauth_nonce'] = nonce
		
		if timestamp:
			authorization['oauth_timestamp'] = timestamp
		
		if tokenKey:
			authorization['oauth_token'] = tokenKey
		
		if oauthExtraParams:
			parts = oauthExtraParams.split('&')
			for p in parts:
				if '=' in p:
					authorization[p.split('=')[0]] = '='.join(p.split('=')[1:])
		
		return urllib.urlencode(authorization)
	
	

############################################################################################
############################################################################################
############################################################################################

class Console(object):
	"""This class implements the GUI to operate with the user."""
	
	####################################################################################
	### CONSTANTS
	####################################################################################
	
	# OAuzz Version
	__VERSION = "1.0"
	
	# Error Code
	__ERRORCODE = "\033[91m** ERROR **\033[0m"
	
	# Information Code
	__INFOCODE = "\033[94m** INFO **\033[0m"
	
	# Default Values
	__ORIGINALVALUES = {
		"CONSUMERKEY" : "", 
		"CONSUMERSECRET" : "",
		"TOKENKEY" : "",
		"TOKENSECRET" : "",
		"SIGNATUREMETHOD" : OAuth.HMAC_SHA1, # Special values
		"VERSION" : "1.0", # Special values
		"TIMESTAMP" : "", # Special values
		"NONCE" : "",
		"EXTRAOAUTHPARAM" : None, # Special values
		"BODYHASH" : "False", # Non fuzzable / Special values
		"OAUTHCALLBACK" : "", # Non fuzzable
		"AUTHORITATIONURL" : "", # Non fuzzable
		"CERTPATH" : "", # Non fuzzable
		"PASSPHRASE" : "", # Non fuzzable
		"METHOD" : "GET",
		"URL" : "",
		"URLPARAM" : None, # Special values
		"HEADER" : None, # Special values
		"BODY" : "",
		"BODYTYPE" : "URLENCODED", # Non fuzzable / Special values
		"REALM" : "",
		"PROXY" : "", # Non fuzzable / Special values
		"FUZZFILE" : "oauzz.dict", # Non fuzzable
		"RESULTFILE" : "results" # Non fuzzable
		}
	
	# Non-fuzzable variables
	__NONFUZZABLE = ["BODYHASH", "OAUTHCALLBACK", "AUTHORITATIONURL", "BODYTYPE", "PROXY", "FUZZFILE", "RESULTFILE", "CERTPATH", "PASSPHRASE"]
	
	# Special values variables
	__SPECIALVALUES = ["SIGNATUREMETHOD", "BODYHASH", "BODYTYPE", "PROXY", "VERSION", "TIMESTAMP", "EXTRAOAUTHPARAM", "URLPARAM", "HEADER"]
	
	# SIGNATUREMETHOD valid values
	__SIGNATUREMETHODVALUES = [OAuth.HMAC_SHA1, OAuth.PLAINTEXT, OAuth.RSA_SHA1]
	
	# BODYTYPE valid values
	__BODYTYPEVALUES = ["URLENCODED", "MULTIPART", "OTHER"]
	
	# VERSION valid values
	__VERSIONVALUES = ["1.0", "2.0"]
	
	# Pattern for FUZZ 
	__FUZZPATTERN = "FUZZ"
	
	
	####################################################################################
	### VARIABLES
	####################################################################################
	
	# Variables defined by the user (with FUZZ pattern)
	__variables = {}
	
	# Variables defined by the user (with correct value - not FUZZ pattern)
	__correctvariables = {}
	
	# Results file
	__resultsFile = None
	
	####################################################################################
	### METHODS
	####################################################################################
	
	####################################################################################
	@staticmethod
	def __welcomeMessage ():
		"""This method prints a welcome message."""
		
		print """
		
           ___        _                             
         .'   `.     / \                            
        /  .-.  \   / _ \    __   _ \033[91m ____   ____   \033[0m
        | |   | |  / ___ \  [  | | |\033[91m[_   ] [_   ]  \033[0m
        \  `-'  /_/ /   \ \_ | \_/ |\033[91m .' /_  .' /_  \033[0m
         `.___.'|____| |____|'.__.' \033[91m[_____][_____] \033[0m
       .............................................
         `:::::::::::::::::::::::::::::::::::::::'
            `:::::::::::::::::::::::::::::::::'

                      La X marca el lugar...
                                by JulGor


Type 'help' to start."""
	
	####################################################################################
	@staticmethod
	def __initializeVariables ():
		"""Initialize the internal variables of the application."""
		
		Console.__variables = {}
		Console.__correctvariables = {}
		
		for key in Console.__ORIGINALVALUES.keys():
			# These variables are lists
			if key in ["EXTRAOAUTHPARAM", "URLPARAM", "HEADER"]:
				Console.__variables[key] = []
				Console.__correctvariables[key] = []
			# These variables aren't fuzzable
			elif key in Console.__NONFUZZABLE:
				Console.__variables[key] = Console.__ORIGINALVALUES[key]
				Console.__correctvariables[key] = Console.__ORIGINALVALUES[key]
			# These variables are fuzzable string
			else:
				Console.__variables[key] = (Console.__ORIGINALVALUES[key],)
				Console.__correctvariables[key] = Console.__ORIGINALVALUES[key]
	
	
	####################################################################################
	@staticmethod
	def __checkSpecialValues (variable, value):
		"""This method checks if the value has the correct form.
		
		@param variable OAuzz variable the user is trying to set up.
		@param value The value which must be checked.
		
		@return True / False pointing if the value is correct or not."""
		
		if variable == "SIGNATUREMETHOD":
			return value in Console.__SIGNATUREMETHODVALUES
		
		if variable == "BODYTYPE":
			return value in Console.__BODYTYPEVALUES
		
		if variable == "BODYHASH":
			return value.lower() in ["true", "false"]
		
		if variable == "PROXY":
			url = urlparse(value)
			try:
				x = int(url.netloc.split(':')[1])
			except:
				return False
				
			return url.scheme.lower() in ['http', 'https']
		
		if variable == "VERSION":
			return value in Console.__VERSIONVALUES
		
		if variable == "TIMESTAMP":
			try:
				x = int(value)
				return True
			except:
				return False
		
		if variable in ["EXTRAOAUTHPARAM", "URLPARAM"]:
			return '=' in value and '?' not in value and '&' not in value
		
		if variable == "HEADER":
			return ': ' in value and value.split(':')[0] and value.split(':')[1]
		
		return True
		
		
	
	####################################################################################
	@staticmethod
	def printMessage (message, code=None):
		"""Print a message in the console.
		
		@param code Code of the message.
		@param message Text of the message.
		"""
		
		if code:
			print "%s - %s" % (code, message)
		
		else:
			print "%s" % (message)
	
	####################################################################################
	@staticmethod
	def __printResultsFuzzingHeader ():
		"""Print the Header of the fuzzing results in standard output and in a file."""
		
		print "\n%s\nStarting fuzzing at %s\n%s\n" % ( '*'*79, strftime("%a, %d %b %Y %H:%M:%S"), '*'*79 )
		Console.__showVariables()
		
		print "\n\nVariable\tOriginal Value\t\tResp. Code\t\tResp. Length\tPayload\n--------\t--------------\t\t----------\t\t------------\t-------"
		
		if Console.__resultsFile:
			try:
				Console.__resultsFile.write ( "\n%s\nStarting fuzzing at %s\n%s\n\n\n" % ( '*'*79, strftime("%a, %d %b %Y %H:%M:%S"), '*'*79 ) )
				Console.__resultsFile.write ( "Variable\tOriginal Value\t\tResp. Code\t\tResp. Length\tPayload\n--------\t--------------\t\t----------\t------------\t-------\n")
			except:
				raise IOError("It wasn't possible to write in result file: %s.log" % Console.__variables["RESULTFILE"])
	
	
	####################################################################################
	@staticmethod
	def __printResultsFuzzingFoot ():
		"""Print the Header of the fuzzing results in standard output and in a file."""
		
		print "\n%s\nFinishing fuzzing at %s\n%s\n\n" % ( '*'*79, strftime("%a, %d %b %Y %H:%M:%S"), '*'*79 )
		
		if Console.__resultsFile:
			try:
				Console.__resultsFile.write ( "\n%s\nFinishing fuzzing at %s\n%s\n\n\n" % ( '*'*79, strftime("%a, %d %b %Y %H:%M:%S"), '*'*79 ) )
			except:
				raise IOError("It wasn't possible to write in result file: %s.log" % Console.__variables["RESULTFILE"])
	
	
	####################################################################################
	@staticmethod
	def __printResultsFuzzing (request, response, parameter, originalValue, payload):
		"""Print the results of a fuzzing request in standard output and in a file.
		
		@param response The response of the server."""
		
		if response:
			body = response.read()
			length = len(body)
			rheader = BaseHTTPRequestHandler.responses[response.code][0]
			
			print "%s%s%d %s%d\t\t%s" % ( 
				( len(parameter)<8 and parameter + '\t\t' or parameter + '\t' ),
				( len(originalValue)<8 and originalValue + '\t\t\t' or (len(originalValue)<16 and originalValue + '\t\t' or originalValue[:15] + '[...]\t') ),
				response.code, 
				( (len(rheader))<4 and rheader + '\t\t\t' or ((len(rheader))<12 and rheader + '\t\t' or rheader[:19] + '\t') ),
				length, 
				payload
				)
			
			rows = [ ( parameter, 
				   originalValue, 
				   response.code, 
				   rheader, 
				   length, 
				   payload,
				   Console.__getRequestString (request),
				   Console.__getResponseString (response) + body
				  ) ]
			
			# Write the result in a log file
			if Console.__resultsFile:
				try:
					Console.__resultsFile.write( "%s%s%d %s%d\t\t%s\n" % ( 
						( len(parameter)<8 and parameter + '\t\t' or parameter + '\t' ),
						( len(originalValue)<8 and originalValue + '\t\t\t' or (len(originalValue)<16 and originalValue + '\t\t' or originalValue[:15] + '[...]\t') ),
						response.code, 
						( (len(rheader))<4 and rheader + '\t\t\t' or ((len(rheader))<12 and rheader + '\t\t' or rheader[:19] + '\t') ),
						length, 
						payload)
						)
				except:
					# Save the request in the database
					if DBHandler.isOpened():
						try:
							DBHandler.insert ( rows )
						except:
							raise sqlite3.DatabaseError ("It wasn't possible to write in the database: %s.db" % Console.__variables["RESULTFILE"])
					
					raise IOError("It wasn't possible to write in result file: %s.log" % Console.__variables["RESULTFILE"])

			# Save the request in the database
			if DBHandler.isOpened():
				try:
					DBHandler.insert ( rows )
				except:
					raise sqlite3.DatabaseError ("It wasn't possible to write in the database: %s.db" % Console.__variables["RESULTFILE"])
	
	
	####################################################################################
	@staticmethod
	def __getResponseString (response):
		"""From a Response object, this method returns a string with its content."""
		
		return "%s\n%s\n%s" % (
			'HTTP/1.1 %d %s' % ( response.code, BaseHTTPRequestHandler.responses[response.code][0] ),
			str(response.info()).encode('utf-8'), 
			response.read().encode('utf-8') 
			) 
		
	
	
	####################################################################################
	@staticmethod
	def __getRequestString (request):
		"""From a Request object, this method returns a string with its content.
		
		@param request The HTTP Request Object (urllib2 request object)..
		
		@return The HTTP request string.
		"""
		
		path = '/'.join(request.get_full_url().split('/')[3:])
		if not path or path[0] != '/':
			path = '/' + path
		
		return "%s %s HTTP/1.1\n%s%s" % ( 
			request.get_method(), 
			path.encode('utf-8'), 
			'\n'.join ([x[0].encode('utf-8') + ": " + x[1].encode('utf-8') for x in request.header_items()]), 
			request.get_data() and '\n\n' + request.get_data().encode('utf-8') or ''
			) 
	
	
	####################################################################################
	@staticmethod
	def __getMultipartBody ():
		"""This method create a multipart body request from a URL-encoded body.
		
		@param body URL-Encoded body.
		@return A pair with the multipart id and the multipart structured body."""
		
		mpbody = ""
		
		# Get a random multipart id
		mpid = randint (100000, 999999)
		mpseparator = "------multipart-boundary-%d" % mpid
		
		# Get a parameter dictionary
		#bodydict = HTTPClient.getParametersDict (body)
		
		Console.printMessage ('Starting multipart body input. Leave blank a "Content-Disposition" to finish.\n')
		
		Console.printMessage (mpseparator)
		
		cd = raw_input("Content-Disposition: ")
		
		while cd:
			
			ct = raw_input("Content-Type [text/plain]: ")
			if not ct:
				ct = "text/plain"
			
			
			value = raw_input("Value: ")
		
			mpbody += mpseparator + "\n"
			mpbody += "Content-Disposition: %s\n" % cd
			mpbody += "Content-Type: %s\n\n" % ct
			mpbody += value + "\n"
			
			cd = raw_input("\nContent-Disposition: ")
		
		
		mpbody += mpseparator + "--\n"
		
		return (mpid, mpbody)
	
	
	####################################################################################
	@staticmethod
	def getVersion ():
		"""This method returns the OAuzz version.
		
		@return The current version of the application."""
		return Console.__VERSION
		
	####################################################################################
	@staticmethod
	def __getVersion ():
		"""
VERSION:
========

Show the version of the application.

Usage:
\tversion
"""
		Console.printMessage ("You are using OAuzz version %s" % Console.__VERSION, Console.__INFOCODE)
	
	
	####################################################################################
	@staticmethod
	def __sendSignedRequest (variables):
		"""Perform the needed steps to make a signed request to a server.
		
		@param Dictionary with the set of needed variables to create the HTTP Request.
		@return A tuple with the information of the HTTP request and the HTTP response."""
		
		# checks for default values and auto-generates...
		
		# nonce
		nonce = ""
		if variables["NONCE"]:
			nonce = variables["NONCE"]
		else:
			nonce = OAuth.generateNonce()
		
		# timestamp
		timestamp = ""
		if variables["TIMESTAMP"]:
			timestamp = variables["TIMESTAMP"]
		else:
			timestamp = OAuth.getTimestamp()
		
		# signaturemethod
		signaturemethod = ""
		if variables["SIGNATUREMETHOD"]:
			signaturemethod = variables["SIGNATUREMETHOD"]
		else:
			signaturemethod = Console.__ORIGINALVALUES["SIGNATUREMETHOD"]
		if signaturemethod == OAuth.RSA_SHA1 and not variables["CERTPATH"]:
			Console.printMessage ("CERTPATH variable must be setted up in RSA-SHA1 signature mode.", Console.__ERRORCODE)
			return
		
		# version
		version = ""
		if variables["VERSION"]:
			version = variables["VERSION"]
		else:
			version = Console.__ORIGINALVALUES["VERSION"]
		
		# method
		method = ""
		if variables["METHOD"]:
			method = variables["METHOD"]
		else:
			method = Console.__ORIGINALVALUES["METHOD"]
		
		# bodyhash
		bodyhash = False
		if variables["BODYHASH"].lower() == "true":
			bodyhash = True
		
		# Check the type of the body (URLENCODED, XML, JSON, multipart...)
		body = variables["BODY"]
		bodytypeOAuth = OAuth.BODY_FORM_URLENCODED
		bodytypeHTTP = HTTPClient.BODY_FORM_URLENCODED
		# If  it's a URL Encoded body, get a dictionary with the parameters
		if variables["BODYTYPE"] == "URLENCODED":
			body = HTTPClient.getParametersDict (body)
			
		# If it's a multipart request, add the correct Content-Type HTTP Header
		if variables["BODYTYPE"] == "MULTIPART" and body:
			bodytypeOAuth = OAuth.BODY_OTHER
			bodytypeHTTP = HTTPClient.BODY_OTHER
			mpseparator = "------multipart-boundary-"
			if '\n' in body and mpseparator in body:
				multipartid = body.split ('\n')[0].split(mpseparator)[1]
				for h in variables["HEADER"]:
					if "Content-Type" in h:
						variables["HEADER"].remove(h)
						break
				variables["HEADER"].append ("Content-Type: multipart/form-data; boundary=----multipart-boundary-%s" % multipartid)
				
		# In other case, unset the 'body' variable
		else:
			bodytypeOAuth = OAuth.BODY_OTHER
			bodytypeHTTP = HTTPClient.BODY_OTHER
			
			
		# Calcule de signature
		signature = OAuth.signRequest (
			url=variables["URL"],
			method=method,
			consumerKey=variables["CONSUMERKEY"],
			consumerSecret=variables["CONSUMERSECRET"],
			tokenKey=variables["TOKENKEY"],
			tokenSecret=variables["TOKENSECRET"],
			signatureMethod=signaturemethod,
			nonce=nonce,
			timestamp=timestamp,
			version=version,
			oauthExtraParams='&'.join(variables["EXTRAOAUTHPARAM"]),
			urlParams='&'.join(variables["URLPARAM"]),
			body=body,
			bodyType=bodytypeOAuth,
			bodyHash=bodyhash,
			certPath=variables["CERTPATH"],
			passphrase=variables["PASSPHRASE"]
			)
		
		
		# Get the Authorization Header
		authorizationHeader = OAuth.getAuthorizationHeader (
			signature=signature, 
			consumerKey=variables["CONSUMERKEY"], 
			tokenKey=variables["TOKENKEY"],
			signatureMethod=signaturemethod,
			nonce=nonce,
			timestamp=timestamp,
			version=version,
			oauthExtraParams='&'.join(variables["EXTRAOAUTHPARAM"]),
			realm=variables["REALM"]
			)
		
		
		# Add the header to the other headers
		headers = HTTPClient.getHeadersDict (variables["HEADER"])
		headers["Authorization"] = authorizationHeader
		
		# Create the final URL
		url = variables["URL"]
		if variables["URLPARAM"]:
			url = url + '?' + '&'.join(variables["URLPARAM"])
		
		# Send the request
		(request, response) = HTTPClient.sendHTTPRequest ( 
			url, 
			body=body,
			bodyType=bodytypeHTTP,
			httpheaders=headers, 
			method=method, 
			proxy=variables["PROXY"]
			)
		
		return ( request , response)
		#return ( [variables["METHOD"], variables["URL"], '&'.join(variables["URLPARAM"]), headers, variables["BODY"]] , response)
	
	
	####################################################################################
	@staticmethod
	def __getCorrectValues ():
		"""Change every FUZZ pattern for the correct value."""
		
		finalvariables = dict(Console.__variables)
		for vname in finalvariables:
			vvalue = finalvariables[vname]
			
			if vvalue and type(vvalue)==type(tuple()):
				for i in range( vvalue[0].count(Console.__FUZZPATTERN) ):
					vvalue[0].replace (Console.__FUZZPATTERN, vvalue[1][i], 1)
				finalvariables[vname] = vvalue[0]
			
			if vvalue and type(vvalue)==type(list()):
				tmplist = []
				for elem in vvalue:
					for i in range( elem[0].count(Console.__FUZZPATTERN) ):
						elem[0].replace (Console.__FUZZPATTERN, elem[1][i], 1)
					tmplist.append(elem)
				finalvariables[vname] = tmplist
		
		return finalvariables
	
	####################################################################################
	@staticmethod
	def __printSyntax ():
		"""
HELP:
=====

Print the Syntax of the application.

Usage:
\thelp
"""
		
		print """
OAuzz %s ( http://code.google.com/p/oauzz/ )

COMMANDS: 
=========

\tCommand\t\t\tDescription
\t-------\t\t\t-----------
\tset VARIABLE VALUE\tSet VARIABLE to VALUE.
\tunset [VARIABLE/S]\tUnset VARIABLE (or all of them).
\tshow [VARIABLE/S]\tShow the value of VARIABLE (or all of them).
\tauthenticate\t\tOAuth Authentication with the server (default 3-legged).
\ttest\t\t\tSend a request with the correct values of each parameter.
\tfuzz\t\t\tRun the fuzzer.
\tselect\t\t\tPerform a SQL Select query over the fuzzing results.
\t\t\t\tEx: select response from results where responsecode=200
\texport\t\t\tExport the database results to CSV, XML or HTML format.
\thelp [COMMAND]\t\tThis help or the specified command help.
\tversion\t\t\tShow the version.
\texit\t\t\tTerminate the application.


OAUTH VARIABLES:
================

\tVariable\t\tFuzzable\tDescription
\t--------\t\t--------\t-----------
\tCONSUMERKEY\t\tYES\t\tConsumer key
\tCONSUMERSECRET\t\tYES\t\tConsumer secret
\tTOKENKEY\t\tYES\t\tToken key which identifies the user (unset it for 2-legged OAuth).
\tTOKENSECRET\t\tYES\t\tToken secret (unset it for 2-legged OAuth).
\tSIGNATUREMETHOD\t\tYES\t\tOAuth Signature Method. Possible values: PLAINTEXT, 
\t\t\t\t\t\tHMAC-SHA1 (default), RSA-SHA1.
\tVERSION\t\t\tYES\t\tOAuth version (default "1.0").
\tTIMESTAMP\t\tYES\t\tOAuth timestamp (unset it if you want the current time).
\tNONCE\t\t\tYES\t\tOAuth nonce (unset it if you want to use a random one for each
\t\t\t\t\t\trequest).
\tEXTRAOAUTHPARAM\t\tYES\t\tExtra OAuth parameters to be included in the OAuth header.
\t\t\t\t\t\t(Ex: "set EXTRAOAUTHPARAM oauth_verifier=5555")
\tBODYHASH\t\tNO\t\tFlag which determines if "oauth_body_hash" must be included
\t\t\t\t\t\tas a OAuth parameter. Possible values: True or False (default).
\tOAUTHCALLBACK\t\tNO\t\tUsed while the OAuth authentication process, in the
\t\t\t\t\t\tgetRequestToken request. To fuzz this value configure it like an
\t\t\t\t\t\tEXTRAOAUTHPARAM parameter.
\tAUTHORITATIONURL\tNO\t\tUsed while the OAuth authentication process. It is the
\t\t\t\t\t\tService Provider URL where the final user must authorize the App.
\t\t\t\t\t\tTo fuzz this value configure it like an EXTRAOAUTHPARAM parameter.
\tCERTPATH\t\tNO\t\tDigital certificate to use with RSA-SHA1 signature mode.


HTTP VARIABLES:
===============

\tVariable\t\tFuzzable\tDescription
\t--------\t\t--------\t-----------
\tMETHOD\t\t\tYES\t\tHTTP method (default GET).
\tURL\t\t\tYES\t\tURL of the service (without any parameters).
\tURLPARAM\t\tYES\t\tParameters used in the URL. Use one SET command per parameter.
\t\t\t\t\t\tEx: SET URLPARAM parameter1=value
\t\t\t\t\t\t    SET URLPARAM parameter2=other_value
\tHEADER\t\t\tYES\t\tExtra HTTP header to use in the request. Use one SET command per
\t\t\t\t\t\theader. Ex:
\t\t\t\t\t\t    SET HEADER MyHeader1: valueheader1
\t\t\t\t\t\t    SET HEADER MyHeader2: valueheader2
\tBODY\t\t\tYES\t\tBody of the request (if needed). Leave it in blank to set up a 
\t\t\t\t\t\tMULTIPART body (Ex: set BODY)
\tBODYTYPE\t\tNO\t\tDefines the Content-Type through different values: URLENCODED, 
\t\t\t\t\t\tMULTIPART or OTHER (used for JSON, XML or other types).
\tREALM\t\t\tYES\t\tIf setted up, it was used to create the Authorization HTTP header.
\tPROXY\t\t\tNO\t\tHTTP proxy through you want to send the requests (Ex.: 
\t\t\t\t\t\t"http://127.0.0.1:8080")


EXTRA VARIABLES:
================

\tVariable\t\tFuzzable\tDescription
\t--------\t\t--------\t-----------
\tFUZZFILE\t\tNO\t\tSpecify a file with fuzzing rules (default oauzz.dict).
\tRESULTFILE\t\tNO\t\tCommon part of the results files name (default: results).


FUZZING NOTES:
==============

  Set the diferent variables with pattern "%s" wherever you want to fuzz.
  The application will ask you for a valid value for each of the fuzzing
  variables.
  
  Example:

	OAuzz > set BODY param1=FUZZ&param2=FUZZ&param3=this_is_not_fuzzable
	Set the original value for FUZZ pattern 1: fuzzable_value_1
	Set the original value for FUZZ pattern 2: fuzzable_value_2
	BODY = param1=fuzzable_value_1&param2=fuzzable_value_2&param3=this_is_not_fuzzable
	OAuzz > show BODY
	BODY = param1=FUZZ&param2=FUZZ&param3=this_is_not_fuzzable
	OAuzz > 


Contact:
========

[Web]           http://laxmarcaellugar.blogspot.com/
[Mail/Google+]  bloglaxmarcaellugar , which is an e-mail address in gmail!com
[twitter]       @laXmarcaellugar
""" % (Console.__VERSION, Console.__FUZZPATTERN)
	
	
	####################################################################################
	@staticmethod
	def __showVariables (variable=None):
		"""
SHOW:
=====

Show the value of the specified variable/s or the value of all of them if no variable is specified.

Usage: 
\tshow [VARIABLE [VARIABLE [...]]]

Examples:
\t* Show the value of all the variables:
\t\tOAuzz > show

\t* Show the value of CONSUMERKEY variable:
\t\tOAuzz > show CONSUMERKEY

\t* Show the value of TOKENKEY and TOKENSECRET variables:
\t\tOAuzz > show TOKENKEY TOKENSECRET
"""
		
		# Construct correct pairs of parameter/value
		extraoauthparams = [ eop[0] for eop in Console.__variables["EXTRAOAUTHPARAM"] ]
		urlparams = [ up[0] for up in Console.__variables["URLPARAM"] ]
		headers = [ h[0] for h in Console.__variables["HEADER"] ]
		body = Console.__variables["BODY"][0]
		if not variable or variable=="BODY" and Console.__variables["BODYTYPE"].lower() == "true":
			body = body.replace('\n', '\n\t\t\t\t')
		
		# All the variables must be shown
		if not variable:
			print """
OAUTH VARIABLES:
================

\tVariable\t\tValue
\t--------\t\t-----
\tCONSUMERKEY\t\t%s
\tCONSUMERSECRET\t\t%s
\tTOKENKEY\t\t%s
\tTOKENSECRET\t\t%s
\tSIGNATUREMETHOD\t\t%s
\tVERSION\t\t\t%s
\tTIMESTAMP\t\t%s
\tNONCE\t\t\t%s
\tEXTRAOAUTHPARAM\t\t%s
\tBODYHASH\t\t%s
\tOAUTHCALLBACK\t\t%s
\tAUTHORITATIONURL\t%s
\tCERTPATH\t\t%s

HTTP VARIABLES:
===============

\tVariable\t\tValue
\t--------\t\t-----
\tMETHOD\t\t\t%s
\tURL\t\t\t%s
\tURLPARAM\t\t%s
\tHEADER\t\t\t%s
\tBODY\t\t\t%s
\tBODYTYPE\t\t%s
\tREALM\t\t\t%s
\tPROXY\t\t\t%s

EXTRA VARIABLES:
================

\tVariable\t\tValue
\t--------\t\t-----
\tFUZZFILE\t\t%s
\tRESULTFILE\t\t%s
""" % (
	Console.__variables["CONSUMERKEY"][0], 
	Console.__variables["CONSUMERSECRET"][0], 
	Console.__variables["TOKENKEY"][0], 
	Console.__variables["TOKENSECRET"][0], 
	Console.__variables["SIGNATUREMETHOD"][0], 
	Console.__variables["VERSION"][0], 
	Console.__variables["TIMESTAMP"][0], 
	Console.__variables["NONCE"][0], 
	"\n\t\t\t\t".join(extraoauthparams), 
	Console.__correctvariables["BODYHASH"],
	Console.__correctvariables["OAUTHCALLBACK"], 
	Console.__correctvariables["AUTHORITATIONURL"], 
	Console.__correctvariables["CERTPATH"], 
	
	Console.__variables["METHOD"][0], 
	Console.__variables["URL"][0], 
	"\n\t\t\t\t".join(urlparams), 
	"\n\t\t\t\t".join(headers),
	body, #Console.__variables["BODY"][0], 
	Console.__variables["BODYTYPE"],
	Console.__variables["REALM"][0],
	Console.__correctvariables["PROXY"],
	
	Console.__correctvariables["FUZZFILE"], 
	Console.__correctvariables["RESULTFILE"]
	)
		
		# Only the specified variable must be shown
		else:
			for var in variable:
				if var not in Console.__variables.keys():
					continue
				if var not in ["EXTRAOAUTHPARAM", "URLPARAM", "HEADER"]:
					Console.printMessage (var.upper() + " = " + Console.__variables[var][0])
				elif var == "EXTRAOAUTHPARAM":
					Console.printMessage (var.upper() + " = " + "\n                  ".join(extraoauthparams) )
				elif var == "URLPARAM":
					Console.printMessage (var.upper() + " = " + "\n           ".join(urlparams) )
				elif var == "HEADER":
					Console.printMessage (var.upper() + " = " + "\n         ".join(headers) )
	
	
	####################################################################################
	@staticmethod
	def __setVariable (variable, value):
		"""
SET:
====

Set a variable with the specified value.

Usage: 
\tset VARIABLE VALUE

Examples:
\t* Set CONSUMERKEY variable to value 'MyConsumerKey':
\t\tOAuzz > set CONSUMERKEY MyConsumerKey

\t* Set BODY variable up with a multipart structured body 
\t\tOAuzz > set BODYTYPE MULTIPART
\t\tOAuzz > set BODY
\t\tStarting multipart body input. Leave blank a "Content-Disposition" to finish.
\t\t------multipart-boundary-999999
\t\tContent-Disposition:
"""
		
		# If it's not a correct variable, it doesn't do anything
		if not variable or variable not in Console.__variables.keys():
			return
		
		# Initialize variables
		fuzzingValues = []
		
		# Check if the user want to use OAuth version 2
		if variable == "VERSION" and value == "2.0":
			Console.printMessage ("OAuth version 2.0 is being developed and it is not a standard right now.\nOAuzz will implement this version when it becomes a standard.\nYou can check its status at: http://oauth.net/2/\n", Console.__INFOCODE)
			return
		
		# Check if it is neccesary ask for the MULTIPART BODY values
		if variable == "BODY" and not value:
			# Ask for the information to create the MULTIPART body
			(multiparid, value) = Console.__getMultipartBody()
			
			# Add a HTTP Header with the correct Content-Type
			multipartHeader = "Content-Type: multipart/form-data; boundary=----multipart-boundary-%d" % multiparid
			Console.__variables["HEADER"].append ( (multipartHeader, fuzzingValues) )
			Console.__correctvariables["HEADER"].append (multipartHeader)
			
			# Set up BODYTYPE to MULTIPART
			Console.__variables["BODYTYPE"] = "MULTIPART"
			Console.__correctvariables["BODYTYPE"] = "MULTIPART"
		
		# If the variable is CERTPATH, the PASSPHRASE must be asked too
		if variable == "CERTPATH":
			passphrase = getpass (prompt="Enter passphrase: ")
			Console.__variables["BODYTYPE"] = passphrase
			Console.__correctvariables["BODYTYPE"] = passphrase

		# There is a FUZZ string in the value
		realValue = value
		if Console.__FUZZPATTERN in value: 
		
			if variable not in Console.__NONFUZZABLE:
			
				# It is necessary to ask for the correct value
				for i in range( value.count (Console.__FUZZPATTERN) ):
					fuzzvalue = raw_input ("Set the original value for %s pattern %d: " % (Console.__FUZZPATTERN, (i+1)))
					fuzzingValues.append ( fuzzvalue )
					realValue = realValue.replace(Console.__FUZZPATTERN, fuzzvalue, 1)
			
			# The variable is not fuzzable
			else:
				Console.printMessage ("%s variable is NOT FUZZABLE." % (variable), Console.__INFOCODE)
		
		# Check if value is rigth for this variable
		if not Console.__checkSpecialValues (variable, realValue):
			Console.printMessage ("The input value for %s is not correct. Write 'help' for help." % variable, Console.__ERRORCODE)
			return
			
		# Is the variable a string?
		if type(Console.__ORIGINALVALUES[variable]) == type(str()):
			
			# It's the BODYHASH variable
			if variable == "BODYHASH":
				if value.lower() == 'false':
					Console.__variables[variable] = "False"
					Console.__correctvariables[variable] = "False"
				elif value.lower() == 'true':
					Console.__variables[variable] = "True"
					Console.__correctvariables[variable] = "True"
				
			elif variable in Console.__NONFUZZABLE:
				Console.__variables[variable] = value
				Console.__correctvariables[variable] = realValue
			
			else:
				Console.__variables[variable] = (value, fuzzingValues)
				Console.__correctvariables[variable] = realValue
			
			Console.printMessage (variable.upper() + " = " + Console.__correctvariables[variable])
		
		# Is the variable a list?
		elif type(Console.__correctvariables[variable]) == type(list()):
			
			Console.__variables[variable].append ( (value, fuzzingValues) )
			Console.__correctvariables[variable].append (realValue)
				
			# Show the setted value
			Console.printMessage ('%s added: "%s"' % (variable.upper(), value) )
	
	
	####################################################################################
	@staticmethod
	def __unsetVariable (variable):
		"""
UNSET:
======

Unset the specified variable/s or all of them if no variable is defined.
Predefined variables are unsetted to default values.

Usage: 
\tunset [VARIABLE [VARIABLE [...]]]

Examples:
\t* Unset all the variables:
\t\tOAuzz > unset

\t* Unset CONSUMERKEY variable:
\t\tOAuzz > unset CONSUMERKEY

\t* Unset SIGNATUREMETHOD and PROXY variables:
\t\tOAuzz > unset SIGNATUREMETHOD PROXY
"""
		
		# If there isn't any variable, clean all the parameters
		if not variable:
			Console.__initializeVariables()
			return
		
		for var in variable:
			
			# It's not a correct variable name
			if not var in Console.__variables.keys():
				continue
			
			# Is the variable a string?
			if type(Console.__ORIGINALVALUES[var]) == type(str()):
				
				# It's a predefined variable
				if var in ["BODYHASH", "BODYTYPE", "SIGNATUREMETHOD", "VERSION", "METHOD", "FUZZFILE", "RESULTFILE"]:
					Console.__variables[var] = (Console.__ORIGINALVALUES[var], [])
					Console.__correctvariables[var] = Console.__ORIGINALVALUES[var]
					Console.printMessage (var.upper() + " = " + Console.__ORIGINALVALUES[var])
				
				else:
					Console.__variables[var] = ("", [])
					Console.__correctvariables[var] = ""
					Console.printMessage (var.upper() + " = ")
				
				# If it's CERTPATH, PASSPHRASE must be unsetted too
				if var == "CERTPATH":
					Console.__variables["PASSPHRASE"] = ("", [])
					Console.__correctvariables["PASSPHRASE"] = ""
			

			# Is the variable a list?
			elif type(Console.__correctvariables[var]) == type(list()):
				
				Console.__variables[var] = []
				Console.__correctvariables[var] = []
				
				# Show the setted value
				Console.printMessage ('%s list cleaned.' % var)
	
	
	
	####################################################################################
	@staticmethod
	def __authenticate ():
		"""Perform the necessary steps to authenticate the user / application"""

		# Check if the mandatory variables are defined
		if not Console.__correctvariables["CONSUMERKEY"] or not Console.__correctvariables["CONSUMERSECRET"] or not Console.__correctvariables["OAUTHCALLBACK"] or not Console.__correctvariables["AUTHORITATIONURL"]:
			Console.printMessage ("The following VARIABLES are mandaroty in OAuth authentication: CONSUMERKEY, CONSUMERSECRET, OAUTHCALLBACK, AUTHORITATIONURL", Console.__ERRORCODE)
			return
		
		# Ask for the number of legs of the authentication 
		legs = raw_input ("Is the OAuth authentication 2 or 3-legged? (2/[3]): ")
		if not legs:
			legs = "3"
		
		######################################################
		# starts getRequestToken call
		
		# Get final values
		finalvariables = dict(Console.__correctvariables)
		
		# Ask for the request token url
		rturl = raw_input ("Enter the get_request_token URL ([%s]): " % (finalvariables["URL"]) )
		if rturl:
			finalvariables["URL"] = rturl
		
		# include callback in extraoauthparam (if it doesn't exist)
		extraoauthparam = list(finalvariables["EXTRAOAUTHPARAM"])
		callback = False
		for eop in extraoauthparam:
			if "oauth_callback" in eop:
				callback = True
				break
		if not callback:
			extraoauthparam.append( "oauth_callback=" + Console.__correctvariables["OAUTHCALLBACK"] )
		finalvariables["EXTRAOAUTHPARAM"] = extraoauthparam
		
		# Send the request
		(request, response) = Console.__sendSignedRequest (finalvariables)
		
		# Check if the response code if was 200 OK
		if response.code != 200:
			Console.printMessage ( 
				"The web server has returned an unexpected response:\n\n%s\n" % Console.__getResponseString(response), 
				Console.__ERRORCODE)
			return 
		
		# Extract the request token and secret
		(tokenKey, tokenSecret) = OAuth.extractTokens (response.read())
		finalvariables["TOKENKEY"] = tokenKey
		finalvariables["TOKENSECRET"] = tokenSecret
		
		# If it is 2-legged authentication, we have finihished
		if legs == "2":
			Console.__variables["TOKENKEY"] = (tokenKey,)
			Console.__variables["TOKENSECRET"] = (tokenSecret,)
			Console.__correctvariables["TOKENKEY"] = tokenKey
			Console.__correctvariables["TOKENSECRET"] = tokenSecret
			Console.printMessage ("You have been successfully authenticated. TOKENKEY and TOKENSECRET have been updated with the correct values.\n", Console.__INFOCODE)
			return
		
		######################################################
		# 3-legged authentication - starts getAccessToken call
		
		print tokenKey, urllib.quote(tokenKey)
		
		# Ask for the OAuth Verifier
		verifier = raw_input("Visit the authorization URL and enter the Oauth Verifier:\n\n%s\n\nVerifier: " % ( Console.__correctvariables["AUTHORITATIONURL"] + '?' + urllib.urlencode ([('oauth_token', tokenKey)]) ) )
		
		# Ask for the request token url
		raurl = raw_input ("Enter the get_access_token URL ([%s]): " % (finalvariables["URL"]) )
		if raurl:
			finalvariables["URL"] = raurl
		
		# remove callback from extraoauthparam and append verifier code
		for eop in extraoauthparam:
			if "oauth_callback" in eop:
				extraoauthparam.remove(eop)
				break
		extraoauthparam.append("oauth_verifier=" + verifier)
		finalvariables["EXTRAOAUTHPARAM"] = extraoauthparam
		
		# Send the request
		(request, response) = Console.__sendSignedRequest (finalvariables)
		
		# Check if the response code if was 200 OK
		if response.code != 200:
			Console.printMessage ( 
				"The web server has returned an unexpected response:\n\n%s\n" % Console.__getResponseString(response), 
				Console.__ERRORCODE)
			return 
		
		# Extract the request token and secret
		(tokenKey, tokenSecret) = OAuth.extractTokens (response.read())
		
		# Update global values
		Console.__variables["TOKENKEY"] = (tokenKey,)
		Console.__variables["TOKENSECRET"] = (tokenSecret,)
		Console.__correctvariables["TOKENKEY"] = tokenKey
		Console.__correctvariables["TOKENSECRET"] = tokenSecret
		
		# Give some feedback...
		Console.printMessage ("You have been successfully authenticated. TOKENKEY and TOKENSECRET have been updated with the correct values.\n", Console.__INFOCODE)
	
	
	
	####################################################################################
	@staticmethod
	def __test ():
		"""
TEST:
=====

Send a HTTP request with the current configuration for each variable.
If some variable/s has been configured with FUZZ pattern, the request
will be send with the final value (not with the FUZZ string).

Usage: 
\ttest
"""
		
		# Check if the mandatory variables are defined
		if not Console.__correctvariables["CONSUMERKEY"] or not Console.__correctvariables["CONSUMERSECRET"] or not Console.__correctvariables["URL"]:
			Console.printMessage ("The following VARIABLES are mandaroty: CONSUMERKEY, CONSUMERSECRET, URL", Console.__ERRORCODE)
			return 
		
		# Create the final values which are going to be sent
		finalvariables = dict(Console.__correctvariables)
		
		# Send the request
		(request, response) = Console.__sendSignedRequest (finalvariables)
		
		# Show the request
		Console.printMessage ( "\nRequest:\n--------\n\n" + Console.__getRequestString (request) )
		
		# And the response
		Console.printMessage ( "\nResponse:\n---------\n\n%s\n" % Console.__getResponseString(response) )
	
	
	####################################################################################
	@staticmethod
	def __fuzz ():
		"""
FUZZ:
=====

Fuzz all the pre-configured parameters using the payloads stored in 
the FUZZFILE dictionary (one payload per line).
The results are displayed and stored in a log file and in a database
allowing SQL querys.

Usage: 
\tfuzz
"""
		
		logerror = False
		dberror = False
		
		# Check if the mandatory variables are defined
		if not Console.__correctvariables["CONSUMERKEY"] or not Console.__correctvariables["CONSUMERSECRET"] or not Console.__correctvariables["URL"]:
			Console.printMessage ("The following VARIABLES are mandaroty: CONSUMERKEY, CONSUMERSECRET, URL", Console.__ERRORCODE)
			return
		
		
		# Try to open the results file
		try:
			if Console.__correctvariables["RESULTFILE"]:
				Console.__resultsFile = open (Console.__correctvariables["RESULTFILE"] + ".log", "a")
		except:
			logerror = True
			Console.printMessage ("Log file (%s.log) could not be opened. Results will NOT be stored in any log file." % Console.__correctvariables["RESULTFILE"], Console.__ERRORCODE)
			Console.__resultsFile = None
		
		# Open the database
		try:
			DBHandler.openDB (Console.__correctvariables["RESULTFILE"] and Console.__correctvariables["RESULTFILE"] + '.db' or 'oauzz.db')
		except:
			dberror = True
			Console.printMessage ("Database file (%s.db) could not be opened. Results will NOT be stored in any database." % Console.__correctvariables["RESULTFILE"], Console.__ERRORCODE)
		
		# Print the Header
		try:
			Console.__printResultsFuzzingHeader()
		except Exception, e:
			if not logerror:
				logerror = True
				Console.printMessage (e, Console.__ERRORCODE)
		
		# Loop where all the variables are fuzzed
		for var in Console.__variables:
			
			# It's a non-fuzzable variable
			if type(Console.__variables[var]) == type(str()):
				continue
			
			# Create a new dictionary from the original one
			tmpvariables = dict(Console.__correctvariables)
			
			# The original value is a string:
			if type(Console.__variables[var]) == type(tuple()) and len(Console.__variables[var])>1:
				
				# Loop over the fuzzing values
				for i in range(len(Console.__variables[var][1])):
					tmp = Console.__variables[var][0]
					for j in range(len(Console.__variables[var][1])):
						if i==j:
							tmp = tmp.replace ( Console.__FUZZPATTERN, Console.__FUZZPATTERN.lower(), 1)
						else:
							tmp = tmp.replace ( Console.__FUZZPATTERN, Console.__variables[var][1][j], 1)
					
					tmpvariables[var] = tmp.replace ( Console.__FUZZPATTERN.lower(), Console.__FUZZPATTERN, 1)
					
					# Perform de fuzzing over the variable
					try:
						Console.__fuzzParameter (tmpvariables, var, Console.__variables[var][1][i])
					except IOError, ioe:
						if not logerror:
							logerror = True
							Console.printMessage (ioe, Console.__ERRORCODE)
					except sqlite3.DatabaseError, dbe:
						if not dberror:
							dberror = True
							Console.printMessage (dbe, Console.__ERRORCODE)
					except:
						DBHandler.closeDB ()
						Console.__resultsFile.close()
						raise
						
			
			# The original value is a list:
			elif type(Console.__variables[var]) == type(list()):
				
				for p in range(len(Console.__variables[var])):
					
					# Create a new list of parameter for this variable
					tmplist = list(Console.__correctvariables[var])
					
					# There is nothing to fuzz
					if not len(Console.__variables[var][p][1]):
						continue
					
					# Loop over the fuzzing values
					for i in range(len(Console.__variables[var][p][1])):
						tmp = Console.__variables[var][p][0]
						for j in range(len(Console.__variables[var][p][1])):
							if i==j:
								tmp = tmp.replace ( Console.__FUZZPATTERN, Console.__FUZZPATTERN.lower(), 1)
							else:
								tmp = tmp.replace ( Console.__FUZZPATTERN, Console.__variables[var][p][1][j], 1)
						
						tmplist[p] = tmp.replace ( Console.__FUZZPATTERN.lower(), Console.__FUZZPATTERN, 1)
						tmpvariables[var] = tmplist
						
						# Perform de fuzzing over the variable
						try:
							Console.__fuzzParameter (tmpvariables, var, Console.__variables[var][p][1][i], p)
						except IOError, ioe:
							if not logerror:
								logerror = True
								Console.printMessage (ioe, Console.__ERRORCODE)
						except sqlite3.DatabaseError, dbe:
							if not dberror:
								dberror = True
								Console.printMessage (dbe, Console.__ERRORCODE)
						except:
							DBHandler.closeDB ()
							Console.__resultsFile.close()
							raise
		
		# Print the Foot
		try:
			Console.__printResultsFuzzingFoot()
		except Exception, e:
			if not logerror:
				logerror = True
				Console.printMessage (e, Console.__ERRORCODE)
		
		# Close the file
		try:
			Console.__resultsFile.close()
		except:
			pass
		
		# Close the database
		try:
			DBHandler.closeDB ()
		except:
			pass
		
	
	####################################################################################
	@staticmethod
	def __fuzzParameter (variables, parameter, originalValue, idx=None):
		"""Perform a fuzzing job over the specified parameter.
		
		@param variables All the variables with their final values.
		@param parameter Parameter which is gonna be fuzzed.
		@param originalValue Correct value of this parameter.
		@param idx Which lists variables, the idx inside the list which is going to be fuzzed."""
		
		# Initialize variables
		exception = None
		
		if idx == None:
			fuzzingValue = variables[parameter]
		else:
			fuzzingValue = variables[parameter][idx]
		
		# Write the header for the results
		try:
			f = open (Console.__correctvariables["FUZZFILE"], 'r')
		except:
			raise IOError("Dictionary file could not be opened. Please, check it before continue.")
		
		# For each payload...
		for payload in f:
			
			# Remove the \n
			payload = payload[:-1]
			
			# Set the payload 
			if idx == None:
				variables[parameter] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload, 1)
			else:
				variables[parameter][idx] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload, 1)
			
			# Send the request
			try:
				(request, response) = Console.__sendSignedRequest (variables)
			except:
				# The execution is stopped if the requests cannot be sent
				raise Exception("Request could not be sent.")
			
			# Print the results of the request
			try:
				Console.__printResultsFuzzing (request, response, parameter, originalValue, payload)
			except Exception, e:
				# The execution is not stopped for an IOError or a DatabaseError
				exception = e
			
			
			# Perform the same with different URL Encoded forms of the payload
			payload_urlencoded1 = HTTPClient.getURLEncodeForm1(payload)
			if payload != payload_urlencoded1:
				if idx == None:
					variables[parameter] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload_urlencoded1, 1)
				else:
					variables[parameter][idx] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload_urlencoded1, 1)
				try:
					(request, response) = Console.__sendSignedRequest (variables)
				except:
					raise Exception("Request could not be sent.")
				
				try:
					Console.__printResultsFuzzing (request, response, parameter, originalValue, payload_urlencoded1)
				except:
					exception = e
			
			payload_urlencoded2 = HTTPClient.getURLEncodeForm2(payload)
			if payload_urlencoded1 != payload_urlencoded2:
				if idx == None:
					variables[parameter] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload_urlencoded2, 1)
				else:
					variables[parameter][idx] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload_urlencoded2, 1)
				try:
					(request, response) = Console.__sendSignedRequest (variables)
				except:
					raise Exception("Request could not be sent.")
				
				try:
					Console.__printResultsFuzzing (request, response, parameter, originalValue, payload_urlencoded2)
				except:
					exception = e
			
			payload_urlencoded3 = HTTPClient.getURLEncodeForm3(payload)
			if payload_urlencoded2 != payload_urlencoded3:
				if idx == None:
					variables[parameter] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload_urlencoded3, 1)
				else:
					variables[parameter][idx] = fuzzingValue.replace (Console.__FUZZPATTERN, originalValue + payload_urlencoded3, 1)
				try:
					(request, response) = Console.__sendSignedRequest (variables)
				except:
					raise Exception("Request could not be sent.")
				
				try:
					Console.__printResultsFuzzing (request, response, parameter, originalValue, payload_urlencoded3)
				except:
					exception = e
			
		# Close the file
		try:
			f.close()
		except:
			pass
		
		# If there was any exception, it is raised
		if exception != None:
			raise exception
		
	
	####################################################################################
	@staticmethod
	def __directSelect (query, showResults=True):
		"""
SELECT:
=======

Perform a SQL query over the DB and print the results.
The table name over the queries are performed is: 

    RESULTS

The columns of that table are:

    VARIABLE - The OAuzz fuzzed variable.
    ORIGINALVALUE - The correct value which the OAuzz variable must be.
    PAYLOAD - Payload used in the HTTP request.
    RESPONSECODE - HTTP response code.
    RESPONSEMESSAGE - HTTP Response Reason-Phrase
    RESPONSELENGTH - HTTP Response length
    REQUEST - HTTP Request
    RESPONSE - HTTP Response

Usage: 
\tselect _usual_SQL_syntax_ FROM RESULTS [WHERE _expression_]

Examples:
\t* Select all the columns from the database
\t\tselect * from results

\t* Select the ORIGINALVALUE and the PAYLOAD where RESPONSECODE is a 200 OK
\t\tselect ORIGINALVALUE, PAYLOAD from RESULTS where RESPONSECODE=200
"""
		
		# Check if the DB is opened and open it if not
		if not DBHandler.isOpened ():
			try:
				DBHandler.openDB (Console.__correctvariables["RESULTFILE"] and Console.__correctvariables["RESULTFILE"].split('.')[0]+'.db' or 'oauzz.db')
			except:
				Console.printMessage ("Database file (%s.db) could not be opened. Check it before trying to access to it." % Console.__correctvariables["RESULTFILE"], Console.__ERRORCODE)
				return
		
		
		# Perform the SQL query
		rows = None
		try:
			rows = DBHandler.directSelect (query)
		except Exception, e:
			Console.printMessage (e, Console.__ERRORCODE)
			return
		
		# Print the results
		if rows != None and showResults:
			
			r = 0
			for row in rows:
				print ("\nRequest %d\n--------" % (r+1)) + '-'*(int (log10(r+1))+1) + '\n'
				
				upquery = query.upper()
				subquery = upquery[upquery.index('SELECT')+6:upquery.index('FROM')].strip()
				
				if subquery == '*':
					subquery = 'VARIABLE, ORIGINALVALUE, RESPONSECODE, RESPONSEMESSAGE, RESPONSELENGTH, PAYLOAD, REQUEST, RESPONSE'
				
				# Print each selected column
				colidx = 0
				if 'VARIABLE' in subquery:
					print "Fuzzable variable:              %s" % row[colidx]
					colidx += 1
				if 'ORIGINALVALUE' in subquery:
					print "Original value:                 %s" % row[colidx]
					colidx += 1
				if 'RESPONSECODE' in subquery:
					print "HTTP Response Status-Code:      %d" % row[colidx]
					colidx += 1
					subquery = subquery.replace ('RESPONSECODE', 'responseCode')
				if 'RESPONSEMESSAGE' in subquery:
					print "HTTP Response Reason-Phrase:    %s" % row[colidx]
					colidx += 1
					subquery = subquery.replace ('RESPONSEMESSAGE', 'responseMessage')
				if 'RESPONSELENGTH' in subquery:
					print "HTTP Response Length:           %s" % row[colidx]
					colidx += 1
					subquery = subquery.replace ('RESPONSELENGTH', 'responseLength')
				if 'PAYLOAD' in subquery:
					print "Payload:                        %s" % row[colidx].encode('utf-8')
					colidx += 1
				if 'REQUEST' in subquery:
					print "Request:\n\n%s\n" % row[colidx].encode('utf-8')
					colidx += 1
				if 'RESPONSE' in subquery:
					print "Response:\n\n%s\n" % row[colidx].encode('utf-8')
					colidx += 1

				# The query didn't return any column (maybe a number or something...)
				if not colidx:
					print "Query result: %s" % str(row)
				r += 1
			
			Console.printMessage ("\n%d rows returned.\n" % r)
			
		return rows
	
	
	####################################################################################
	@staticmethod
	def __exportResults (format=None, query=None):
		"""
EXPORT:
=======

Export the database results to the supported formats (HTML, XML and CSV).

Usage: 
\texport [CSV|XML|HTML [select * from results where _expression_]]

Examples:
\t* Export results to every formats
\t\texport

\t* Export results to only CSV format
\t\texport CSV

\t* Export results to XML format avoiding results with a payload like ']]>'
\t\texport XML select * from results where payload not like '%]]>%'
"""
		
		# Check the query
		if query and not query.lower().startswith('select * from results where'):
			Console.printMessage ("Syntax incorrect. Make calls similar to:\n\texport XML select * from results where ...\n", Console.__ERRORCODE)
			return
		elif not query: 
			query = "SELECT * FROM RESULTS"
		
		# Get the database content
		rows = Console.__directSelect (query, showResults=False)
		
		# Export to CSV
		if not format or format == "csv":
			
			try:
				fcsv = open (Console.__correctvariables["RESULTFILE"] + ".csv", "w")
			except:
				raise IOError("CSV file (%s.csv) could not created. Export operation was canceled." % Console.__correctvariables["RESULTFILE"], Console.__ERRORCODE)
				return
			
			# Print the Header of the CSV file
			try:
				fcsv.write ('"Variable";"OriginalValue";"Payload";"ResponseCode";"ResponseMessage";"ResponseLength";"Request";"Response"\n')
			
				# Check the results
				if not rows:
					Console.printMessage ("No result was found in the database. CSV file was created with no results.", Console.__INFOCODE)
					fcsv.close()
					return
				
				# Write each row...
				for row in rows:
					
					fcsv.write ('"%s";"%s";"%s";"%s";"%s";"%s";"%s";"%s"\n' % (
						row[0].encode('utf-8'), # Variable
						row[1].replace('"', '""').encode('utf-8'), # OriginalValue
						row[5].replace('"', '""').encode('utf-8'), # Payload
						row[2], # ResponseCode
						row[3].encode('utf-8'), # ResponseMessage
						row[4], # ResponseLength
						row[6].replace('"', '""').encode('utf-8'), # Request
						row[7].replace('"', '""').replace('\r', '').encode('utf-8') # Response
						) )
				
				Console.printMessage ("CSV file was create successfully.", Console.__INFOCODE)
				
				# Close the file
				fcsv.close()
			except:
				raise
		
		# Export to XML
		if not format or format == "xml":
			
			try:
				fxml = open (Console.__correctvariables["RESULTFILE"] + ".xml", "w")
			except:
				raise IOError("XML file (%s.xml) could not created. Export operation was canceled." % Console.__correctvariables["RESULTFILE"], Console.__ERRORCODE)
				return
			
			# Print the Header of the XML file
			try:
				fxml.write ('<?xml version="1.0" encoding="UTF-8" ?>\n<oauzz_results>')
			
				# Check the results
				if not rows:
					Console.printMessage ("No result was found in the database. XML file was created with no results.", Console.__INFOCODE)
					fxml.write ('</oauzz_results>\n')
					fxml.close()
					return
				
				# Write each row...
				count = 1
				for row in rows:
					
					if "]]>" in row[5]:
						Console.printMessage ("A payload was detected with the string ']]>' so the final XML will be malformed (row %d)." % count, Console.__INFOCODE)
						Console.printMessage ("Use advanced export options to avoid the problem.", Console.__INFOCODE)
					
					fxml.write ('  <oauzz_result>\n    <oauzz_variable>%s</oauzz_variable>\n    <originalValue><![CDATA[%s]]></originalValue>\n    <payload><![CDATA[%s]]></payload>\n    <responseCode>%s</responseCode>\n    <responseMessage>%s</responseMessage>\n    <responseLength>%s</responseLength>\n    <request><![CDATA[%s]]></request>\n    <response><![CDATA[%s]]></response>\n  </oauzz_result>\n' % (
						row[0].encode('utf-8'), # Variable
						row[1].encode('utf-8'), # OriginalValue
						row[5].encode('utf-8'), # Payload
						row[2], # ResponseCode
						row[3].encode('utf-8'), # ResponseMessage
						row[4], # ResponseLength
						row[6].encode('utf-8'), # Request
						row[7].encode('utf-8')  # Response
						) )
					
					count += 1
				
				fxml.write ('</oauzz_results>\n')
					
				Console.printMessage ("XML file was create successfully.", Console.__INFOCODE)
				
				# Close the file
				fxml.close()
			except:
				raise
		
		# Export to HTML
		if not format or format == "html":
			
			try:
				fhtml = open (Console.__correctvariables["RESULTFILE"] + ".html", "w")
			except:
				raise IOError("HTML file (%s.html) could not created. Export operation was canceled." % Console.__correctvariables["RESULTFILE"], Console.__ERRORCODE)
				return
			
			try:
				# Print the begining of the HTML file
				fhtml.write ('''<html lang="en"><head><meta charset="utf-8"><title>OAuzz Report</title><meta name="description" content="OAuzz report"><meta name="author" content="OAuzz"><!-- Styles --><style type="text/css">body {padding-top: 60px;padding-bottom: 40px;}.container{width: 940px;margin-right: auto;margin-left: auto;zoom: 1;}.hero-unit {padding: 60px;margin-bottom: 30px;-webkit-border-radius: 6px;-moz-border-radius: 6px;border-radius: 6px;border: 1px solid #dddddd;}.row {margin-left: -20px;*zoom: 1;}[class*="span"] {float: left;margin-left: 20px;}.span12 {width: 940px;}.btn {display: inline-block;*display: inline;padding: 4px 10px 4px;margin-bottom: 0;*margin-left: .3em;font-size: 13px;line-height: 18px;*line-height: 20px;color: #333333;text-align: center;text-shadow: 0 1px 1px rgba(255, 255, 255, 0.75);vertical-align: middle;cursor: pointer;background-color: #f5f5f5;*background-color: #e6e6e6;background-image: -ms-linear-gradient(top, #ffffff, #e6e6e6);background-image: -webkit-gradient(linear, 0 0, 0 100%, from(#ffffff), to(#e6e6e6));background-image: -webkit-linear-gradient(top, #ffffff, #e6e6e6);background-image: -o-linear-gradient(top, #ffffff, #e6e6e6);background-image: linear-gradient(top, #ffffff, #e6e6e6);background-image: -moz-linear-gradient(top, #ffffff, #e6e6e6);background-repeat: repeat-x;border: 1px solid #cccccc;*border: 0;border-color: rgba(0, 0, 0, 0.1) rgba(0, 0, 0, 0.1) rgba(0, 0, 0, 0.25);border-color: #e6e6e6 #e6e6e6 #bfbfbf;border-bottom-color: #b3b3b3;-webkit-border-radius: 4px;-moz-border-radius: 4px;border-radius: 4px;filter: progid:dximagetransform.microsoft.gradient(startColorstr='#ffffff', endColorstr='#e6e6e6', GradientType=0);filter: progid:dximagetransform.microsoft.gradient(enabled=false);*zoom: 1;-webkit-box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2), 0 1px 2px rgba(0, 0, 0, 0.05);-moz-box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2), 0 1px 2px rgba(0, 0, 0, 0.05);box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2), 0 1px 2px rgba(0, 0, 0, 0.05);}table {max-width: 100%;background-color: transparent;border-collapse: collapse;border-spacing: 0;}.table {width: 100%;margin-bottom: 18px;}.table th,.table td {padding: 8px;line-height: 18px;text-align: left;vertical-align: top;border-top: 1px solid #dddddd;}.table th {font-weight: bold;background-color: #C3DCE8;}.table thead th {vertical-align: bottom;}.table caption + thead tr:first-child th,.table caption + thead tr:first-child td,.table colgroup + thead tr:first-child th,.table colgroup + thead tr:first-child td,.table thead:first-child tr:first-child th,.table thead:first-child tr:first-child td {border-top: 0;}.table tbody + tbody {border-top: 2px solid #dddddd;}.table-bordered {border: 1px solid #dddddd;border-collapse: separate;*border-collapse: collapsed;border-left: 0;-webkit-border-radius: 4px;-moz-border-radius: 4px;border-radius: 4px;}.table-bordered th,.table-bordered td {border-left: 1px solid #dddddd;}.table-bordered caption + thead tr:first-child th,.table-bordered caption + tbody tr:first-child th,.table-bordered caption + tbody tr:first-child td,.table-bordered colgroup + thead tr:first-child th,.table-bordered colgroup + tbody tr:first-child th,.table-bordered colgroup + tbody tr:first-child td,.table-bordered thead:first-child tr:first-child th,.table-bordered tbody:first-child tr:first-child th,.table-bordered tbody:first-child tr:first-child td {border-top: 0;}.table-bordered thead:first-child tr:first-child th:first-child,.table-bordered tbody:first-child tr:first-child td:first-child {-webkit-border-top-left-radius: 4px;border-top-left-radius: 4px;-moz-border-radius-topleft: 4px;}.table-bordered thead:first-child tr:first-child th:last-child,.table-bordered tbody:first-child tr:first-child td:last-child {-webkit-border-top-right-radius: 4px;border-top-right-radius: 4px;-moz-border-radius-topright: 4px;}.table-bordered thead:last-child tr:last-child th:first-child,.table-bordered tbody:last-child tr:last-child td:first-child {-webkit-border-radius: 0 0 0 4px;-moz-border-radius: 0 0 0 4px;border-radius: 0 0 0 4px;-webkit-border-bottom-left-radius: 4px;border-bottom-left-radius: 4px;-moz-border-radius-bottomleft: 4px;}.table-bordered thead:last-child tr:last-child th:last-child,.table-bordered tbody:last-child tr:last-child td:last-child {-webkit-border-bottom-right-radius: 4px;border-bottom-right-radius: 4px;-moz-border-radius-bottomright: 4px;}pre {padding: 0 3px 2px;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;font-size: 12px;color: #333333;-webkit-border-radius: 3px;-moz-border-radius: 3px;border-radius: 3px;display: block;padding: 8.5px;margin: 0 0 9px;font-size: 12.025px;line-height: 18px;word-break: break-all;word-wrap: break-word;white-space: pre;white-space: pre-wrap;background-color: #f5f5f5;border: 1px solid #ccc;border: 1px solid rgba(0, 0, 0, 0.15);-webkit-border-radius: 4px;-moz-border-radius: 4px;border-radius: 4px;}</style><script>function expand (obj) {var tbody = obj.parentNode.parentNode.parentNode.tBodies[1];if (tbody.style.display == "none"){tbody.style.display = "table-row-group";}else{tbody.style.display = "none";}}function expandall () {var ths = document.getElementsByName ('tableHeader');for (x in ths)ths[x].parentNode.parentNode.parentNode.tBodies[1].style.display = "table-row-group";}function collapseall () {var ths = document.getElementsByName ('tableHeader');for (x in ths)ths[x].parentNode.parentNode.parentNode.tBodies[1].style.display = "none";}</script></head><body><div class="container">    <!-- Header --><div class="hero-unit"><a href="http://code.google.com/p/oauzz/"><img src="http://code.google.com/p/oauzz/logo?cct=1339942732" alt="OAuzz" width="250px"/></a><p>The fuzzer for OAuth based applications.</p></div><!-- Resultados --><div class="row"><div class="span12"><h2><p style="float: left">OAuzz Results:</p><p style="float: right"><button class="btn" onclick="javascript:collapseall()">Collapse all</button><button class="btn" onclick="javascript:expandall()">Expand all</button></p></h2></div></div><div class="row"><div class="span12">''')
			
				# Check the results
				if not rows:
					Console.printMessage ("No result was found in the database. HTML file was created with no results.", Console.__INFOCODE)
					fhtml.write ('</div></div><hr><footer><p>&copy; <a href="http://code.google.com/p/oauzz/">OAuzz</a> 2012 <a style="float: right" href="http://laxmarcaellugar.blogspot.com.es/">La X marca el lugar</a></p></footer></div> <!-- /container --></body></html>\n')
					fhtml.close()
					return
				
				# Write each row...
				for row in rows:
					
					payload = row[5].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").encode('utf-8')
					request = row[6].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").encode('utf-8')
					response = row[7].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").encode('utf-8')
					fhtml.write ('<div><table class="table table-bordered"><tr><th colspan="2" onclick="javascript:expand(this)" name="tableHeader">[%s] %s</th></tr><tbody  style="display:none;"><tr><td width="130px">Variable:</td><td>%s</td></tr><tr><td width="130px">Original Value:</td><td>%s</td></tr><tr><td width="130px">Payload:</td><td><pre>%s</pre></td></tr><tr><td width="130px">Response Code:</td><td>%d %s</td></tr><tr><td width="130px">Request:</td><td><pre>%s</pre></td></tr><tr><td width="130px">Response:</td><td><pre>%s</pre></td></tr></tbody></table></div>\n' % (
						row[0].encode('utf-8'), payload, # Table Header
						row[0].encode('utf-8'), # Variable
						row[1].encode('utf-8'), # OriginalValue
						payload, # Payload
						row[2], # ResponseCode
						row[3].encode('utf-8'), # ResponseMessage
						request, # Request
						response  # Response
						) )
					
				
				fhtml.write ('</div></div><hr><footer><p>&copy; <a href="http://code.google.com/p/oauzz/">OAuzz</a> 2012 <a style="float: right" href="http://laxmarcaellugar.blogspot.com.es/">La X marca el lugar</a></p></footer></div> <!-- /container --></body></html>\n')
					
				Console.printMessage ("HTML file was create successfully.", Console.__INFOCODE)
				
				# Close the file
				fhtml.close()
			except:
				raise
	
	
	
	####################################################################################
	@staticmethod
	def __launchCommand (command):
		"""This method executes an input command.
		
		@param command The command which has to be executed.
		@return True or False if the app has to finish."""
		
		# Split the command
		parts = command.split()
		if len(parts) == 1:
			parts = [command.strip()]
		parts[0] = parts[0].lower()
		
		# EXIT - Leave the application
		if command in ("quit", "exit"):
			return True
		
		# HELP - Show the help
		elif parts[0].startswith("help"):
			
			# Help of a command
			if len(parts) == 2 and parts[1] in ("help", "version", "select", "show", "set", "unset", "authenticate", "fuzz", "test", "export"):
				if parts[1] == "help":
					print Console.__printSyntax.__doc__
					
				if parts[1] == "version":
					print Console.__getVersion.__doc__
					
				if parts[1] == "select":
					print Console.__directSelect.__doc__
				
				if parts[1] == "show":
					print Console.__showVariables.__doc__
				
				if parts[1] == "set":
					print Console.__setVariable.__doc__
				
				if parts[1] == "unset":
					print Console.__unsetVariable.__doc__
				
				if parts[1] == "authenticate":
					print Console.__authenticate.__doc__
				
				if parts[1] == "fuzz":
					print Console.__fuzz.__doc__
				
				if parts[1] == "test":
					print Console.__test.__doc__
				
				if parts[1] == "export":
					print Console.__exportResults.__doc__
				
			# Wrong sintax or main help
			else:
				Console.__printSyntax()
		
		# VERSION - Show the version
		elif parts[0] == "version":
			Console.__getVersion()
		
		# FUZZ - Start fuzzing
		elif parts[0] == "fuzz":
			Console.__fuzz()
		
		# TEST - Send a test request (without fuzzing)
		elif parts[0] == "test":
			Console.__test()
		
		# AUTHENTICATE - Follow the authentication flow
		elif parts[0] == "authenticate":
			Console.__authenticate ()
		
		# SHOW - Show the variables' values
		elif parts[0] == "show":
			parts = command.upper().split()
			Console.__showVariables (parts[1:])
		
		# SET - Set a variable
		elif parts[0] == "set" and len(parts[1:]) >= 1:
			value = " ".join(parts[2:])
			
			# Check the syntax...
			if value.startswith('"') or value.endswith ('"'):
				
				# Incorrect: it starts with " but doesn't finish with "
				if not value.startswith('"') or not value.endswith ('"'):
					Console.__printSyntax()
					return False
				
				# Incorrect: it starts and finishes with ", but there are more "'s
				elif len(value.split('"')) > 3:
					Console.__printSyntax()
					return False
				
				# Correct
				else:
					value = value.strip('"')
			
			elif  value.startswith("'") or value.endswith ("'"):
				
				# Incorrect: it starts with ' but doesn't finish with '
				if not value.startswith("'") or not value.endswith ("'"):
					Console.__printSyntax()
					return False
				
				# Incorrect: it starts and finishes with ', but there are more ''s
				elif len(value.split("'")) > 3:
					Console.__printSyntax()
					return False
				
				# Correct
				else:
					value = value.strip("'")
				
			Console.__setVariable ( parts[1].upper(), value )
		
		# UNSET - Unset a variable
		elif parts[0] == "unset":
			parts = command.upper().split()
			Console.__unsetVariable (parts[1:])
		
		# SELECT - Direct SQL SELECT statement
		elif parts[0] == "select":
			Console.__directSelect (command)
	
		# EXPORT - Export the DB results to a CSV/XML file
		elif parts[0] == "export":
			if len(parts) == 2:
				Console.__exportResults (parts[1].lower())
			elif len(parts) > 2:
				Console.__exportResults (parts[1].lower(), ' '.join(parts[2:]))
			else:
				Console.__exportResults ()
		
		return False
	
	
	####################################################################################
	@staticmethod
	def startConsole ():
		"""Initialize the console."""
		
		# Printe the welcome message
		Console.__welcomeMessage ()
		
		# Initialize with the default values
		Console.__initializeVariables ()
		
		# Check if there is some input file and execute it
		if len (sys.argv) > 1:
			
			# It accepts more than one script
			for path in sys.argv[1:]:
				
				try:
					# Open the script
					script = open (path, 'r')
					
					# Launch the command
					for command in script:
						if command.strip() and command.strip()[0] != '#':
							Console.printMessage ("OAuth > %s" % command.strip())
							Console.__launchCommand (command.strip())
				except:
					Console.printMessage ("The input file '%s' could NOT be opened." % path, Console.__ERRORCODE)
					
		# Loop of the application (the console)
		end = False
		while not end:
			try:
				# Read the command
				command = raw_input("OAuzz > ")
				
				if not command:
					continue
				
				end = Console.__launchCommand (command.strip())
			
			except KeyboardInterrupt:
				print # Print one blank line to start in a new line
			
			except Exception, e:
				Console.printMessage (e, Console.__ERRORCODE)


	
	


############################################################################
# Main application
############################################################################

# Launch the console
if __name__ == '__main__':
	Console.startConsole()
	

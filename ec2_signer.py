#!/usr/bin/env python

# Copyright (c) 2012 Jeff Kramer

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import hmac
import hashlib
import base64
import urllib
import os
import urlparse
import argparse
import time
import xml.dom.minidom

def sign_url(args,ec2_url,access_key,secret_key):
	'''signs an ec2 url request'''
	ec2_url = list(urlparse.urlparse(ec2_url))
	if ec2_url[2] == '': ec2_url[2] = '/'
	ec2_path = ec2_url[1]+ec2_url[2]
	escaped_args = []
	timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
	args += ["SignatureMethod=HmacSHA256", "SignatureVersion=2",
                "Version=2011-05-15",
                "AWSAccessKeyId="+access_key,
                "Timestamp="+timestamp]
	for arg in args:
		name,value = arg.split("=",1)
		escaped_args.append(urllib.quote_plus(name)+
				'='+urllib.quote_plus(value))
	escaped_args.sort()
	query = '&'.join(escaped_args)
	signable = "\n".join(['GET',ec2_url[1],ec2_url[2],query])
	signature = hmac.new(key=secret_key, msg=signable,
		digestmod=hashlib.sha256).digest()
	signature = urllib.quote_plus(base64.b64encode(signature))
	return str(ec2_url[0]+'://'+ec2_url[1]+ec2_url[2]+'?'+query
			+'&Signature='+signature)

def make_request(url):
	return urllib.urlopen(url).read()

def make_request_pretty(url):
	return xml.dom.minidom.parse(urllib.urlopen(url)).toprettyxml()

# Parse our arguments.

parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description='''
Sign and optionally request responses from EC2 API endpoints.

examples:
  Add a KeyPair named mykeypair:
  ec2_signer.py Action=CreateKeyPair KeyName=newkeypair
	
  List Instances:
  ec2_signer.py Action=DescribeInstances

  Associate Address with Instance:
  ec2_signer.py Action=AssociateAddress PublicIp=1.1.1.1 InstanceId=xyz''',
		epilog="note:\n  EC2_ACCESS_KEY, EC2_SECRET_KEY and EC2_URL environment\n"+
		"  variables must be set.")
parser.add_argument('arguments', metavar='n=v', type=str, nargs='+',
		help="name=value pairs for request")
parser.add_argument('-r',dest='request', action='store_true',
		help='make the request and print the response')
parser.add_argument('-p',dest='request_pretty', action='store_true',
		help='make the request and pretty print response')
args = parser.parse_args()

# Ensure our environment variables are set.

required_env = ("EC2_ACCESS_KEY","EC2_SECRET_KEY","EC2_URL")

for env in required_env:
	if not os.getenv(env):
		print "Error:", env, "environment variable must be set."
		raise SystemExit

# Do the work.

signed_url = sign_url(args.arguments,os.getenv("EC2_URL"),
		os.getenv('EC2_ACCESS_KEY'),os.getenv("EC2_SECRET_KEY"))

if args.request:
	print "Signed URL\n--------"
	print signed_url
	print "\nResponse\n--------"
	print make_request(signed_url)
elif args.request_pretty:
	print "Signed URL\n--------"
	print signed_url
	print "\nResponse\n--------"
	print make_request_pretty(signed_url)
else:
	print signed_url


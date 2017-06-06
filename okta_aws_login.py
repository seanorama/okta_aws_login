#!/usr/bin/env python3
import argparse
import base64
import configparser
import getpass
import logging
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

import boto3
import requests
from bs4 import BeautifulSoup

##########################################################################
# Args

parser = argparse.ArgumentParser(
    description = "Gets a STS token to use for AWS CLI based "
                  "on a SAML assertion from Okta")

parser.add_argument(
    '--username', '-u',
    help = "The username to use when logging into Okta. The username can "
           "also be set via the OKTA_USERNAME env variable. If not provided "
           "you will be prompted to enter a username."
)

parser.add_argument(
    '--profile', '-p',
    help = "The name of the profile to use when storing the credentials in "
           "the AWS credentials file. If not provided then the name of "
           "the role assumed will be used as the profile name."
)

parser.add_argument(
    '--verbose', '-v',
    action = 'store_true',
    help = "If set, will print a message about the AWS CLI profile "
           "that was created."
)

parser.add_argument(
    '--configure', '-c',
    action = 'store_true',
    help = "If set, will prompt user for configuration parameters "
            " and then exit."
)


args = parser.parse_args()

##########################################################################

### Variables ###
# file_root: Path in which all file interaction will be relative to.
# Defaults to the users home dir.
file_root = expanduser("~")
# okta_aws_login_config_file: The file were the config parameters for the 
# okta_aws_login tool is stored
okta_aws_login_config_file = file_root + '/.okta_aws_login_config'
# aws_config_file: The file where this script will store the temp
# credentials under the saml profile.
aws_config_file = file_root + '/.aws/credentials'
# sid_cache_file: The file where the Okta sid is stored.
# only used if cache_sid is True.
sid_cache_file = file_root + '/.okta_sid'
###

def get_arns_from_assertion(assertion):
    """Parses a base64 encoded SAML Assertion and extracts the role and 
    principle ARNs to be used when making a request to STS.
    Returns a dict with RoleArn, PrincipalArn & SAMLAssertion that can be 
    used to call assume_role_with_saml"""
    # Parse the returned assertion and extract the principle and role ARNs
    root = ET.fromstring(base64.b64decode(assertion))
    urn = "{urn:oasis:names:tc:SAML:2.0:assertion}"
    urn_attribute = urn + "Attribute"
    urn_attributevalue = urn + "AttributeValue"
    role_url = "https://aws.amazon.com/SAML/Attributes/Role"
    for saml2attribute in root.iter(urn_attribute):
        if (saml2attribute.get('Name') == role_url):
            for saml2attributevalue in saml2attribute.iter(urn_attributevalue):
                arn_text = saml2attributevalue.text
    arns = arn_text.split(',')
    # Create dict to be used to call assume_role_with_saml
    arn_dict = {}
    for arn in arns:
        if ":role/" in arn:
            arn_dict['RoleArn'] = arn
        elif ":saml-provider/":
            arn_dict['PrincipalArn'] = arn
    arn_dict['SAMLAssertion'] = assertion
    return arn_dict

def get_saml_assertion(response):
    """Parses a requests.Response object that contains a SAML assertion.
    Returns an base64 encoded SAML Assertion if one is found"""
   # Decode the requests.Response object and extract the SAML assertion
    soup = BeautifulSoup(response.text, "html.parser")
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            return inputtag.get('value')

def get_sid_from_file(sid_cache_file):
    """Checks to see if a file exists at the provided path. If so file is read
    and checked to see if the contents looks to be a valid sid.
    if so sid is returned"""
    if os.path.isfile(sid_cache_file) == True:
        with open(sid_cache_file) as sid_file:
            sid = sid_file.read()
            if len(sid) == 25:
                return sid

def get_sts_token(RoleArn,PrincipalArn,SAMLAssertion):
    """Use the assertion to get an AWS STS token using Assume Role with SAML
    returns a Credentials dict with the keys and token"""
    sts_client = boto3.client('sts')
    response = sts_client.assume_role_with_saml(RoleArn=RoleArn,
                                                PrincipalArn=PrincipalArn,
                                                SAMLAssertion=SAMLAssertion)
    Credentials = response['Credentials']
    return Credentials

def get_user_creds():
    """Get's creds for Okta login from the user. Retruns user_creds dict"""
    # Check to see if the username arg has been set, if so use that
    if args.username is not None:
        username = args.username
    # Next check to see if the OKTA_USERNAME env var is set
    elif os.environ.get("OKTA_USERNAME") is not None:
        username = os.environ.get("OKTA_USERNAME")
    # Otherwise just ask the user
    else:
        username = input("Username: ")
    # Set prompt to include the user name, since username could be set
    # via OKTA_USERNAME env and user might not remember.
    passwd_prompt = "Password for {}: ".format(username)
    password = getpass.getpass(prompt=passwd_prompt)
    if len(password) == 0:
        print( "Password must be provided")
        sys.exit(1)
    # Build dict and return in
    user_creds = {}
    user_creds['username'] = username
    user_creds['password'] = password
    return user_creds

def get_user_input(message,default):
    """formats message to include default and then prompts user for input
    via keyboard with message. Returns user's input or if user doesn't
    enter input will return the default."""
    message_with_default = message + " [{}]: ".format(default)
    user_input = input(message_with_default)
    print("")
    if len(user_input) == 0:
        return default
    else:
        return user_input

def okta_cookie_login(sid,idp_entry_url):
    """Attempts a login using the provided sid cookie value. Returns a
    requests.Response object. The Response object may or may not be a
    successful login containing a SAML assertion"""
    # Create Cookie Dict and add sid value
    cookie_dict = {}
    cookie_dict['sid'] = sid
    # Initiate session handler
    session = requests.Session()
    # make request to login page with sid cookie
    response = session.get(idp_entry_url,verify=True,cookies=cookie_dict)
    return response

def okta_mfa_login(password_login_response,app):
    """Prompt user for MFA token generated by either Okta Verify
    or Google Authenticator and construcuts MFA login request
    from entered passcode and details extracted from provided requests.Response
    object. Returns a requests.Response object of the response after login"""
    # Initiate session handler
    session = requests.Session()
    soup = BeautifulSoup(password_login_response.text, "html.parser")
    cookie_dict = {}
    cookie_dict['sid'] = password_login_response.cookies['sid']
    headers_dict = {}
    headers_dict['referer'] = password_login_response.url
    payload_dict = {}
    # Look for the _xsrfToken which we POST along with the passcode
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == '_xsrfToken'):
            xsrfToken = inputtag.get('value')
    payload_dict['_xsrfToken'] = xsrfToken
    # also need to set a header with the info
    headers_dict['X-Okta-Xsrftoken'] = xsrfToken
    # build idpmfaformsubmiturl where the login info will be POSTed
    for inputtag in soup.find_all(re.compile('(FORM|form)')):
       action = inputtag.get('action')
    idpmfaformsubmiturl = "https://{}{}".format(
                           urlparse(password_login_response.url).netloc
                           ,action)
    # Prompt user for the passcode
    passcode = input("Enter your {} code: ".format(app))
    # determine if the POST data name the passcode
    # it's either passcode or code depending on the auth settings
    for inputtag in soup.find_all('input'):
        if (
            inputtag.get('name') == 'passcode'
            or inputtag.get('name') == 'code'
            ):
            codename = inputtag.get('name')
    payload_dict[codename] = passcode
    # POST MFA login and return response
    mfa_response = session.post(idpmfaformsubmiturl, headers=headers_dict,
                           data=payload_dict, cookies=cookie_dict, verify=True)
    # check to see if the passcode was incorrect, if so complain and exit
    if "passcode doesn't match our records" in mfa_response.text:
        print("Incorrect passcode!")
        sys.exit(1)
    # Once MFA login is successful, call the login url while providing the sid
    login_url = password_login_response.history[1].url
    cookie_response = okta_cookie_login(mfa_response.cookies['sid'],
                                        login_url)
    return cookie_response

def okta_password_login(username,password,idp_entry_url):
    """Parses the idp_entry_url and performs a login with the creds
    provided by the user. Returns a requests.Response object that ideally
    contains a SAML assertion"""
    # Initiate session handler
    session = requests.Session()
    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    formresponse = session.get(idp_entry_url, verify=True)
    # Capture the idpauthformsubmiturl,
    # which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url
    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, "html.parser")
    payload_dict = {}
    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        if "user" in name.lower():
            payload_dict[name] = username
        elif "pass" in name.lower():
            payload_dict[name] = password
        else:
            #Simply populate the parameter with the existing value
            #(picks up hidden fields in the login form)
            payload_dict[name] = value
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
    parsedurl = urlparse(idp_entry_url)
    idpauthformsubmiturl = "{scheme}://{netloc}{action}".format(
                                                scheme=parsedurl.scheme,
                                                netloc=parsedurl.netloc,
                                                action=action)
    # Performs the submission of the IdP login form with the above post data
    response = session.post(idpauthformsubmiturl, data=payload_dict,
                            verify=True)
    # Check the response to see if the login was successful or
    # if MFA login is needed
    if "Sign in failed!" in response.text:
        print("Sign in failed!")
        sys.exit(1)
    elif "Okta Verify code" in response.text:
        response = okta_mfa_login(response,"Okta Verify")
    elif "Google Authenticator code" in response.text:
        response = okta_mfa_login(response,"Google Authenticator")
    elif "text message verification code" in response.text:
        send_sms_passcode(response)
        print("Sending passcode via text message")
        response = okta_mfa_login(response,"text message")
    return response

def send_sms_passcode(password_login_response):
    """Has Okta send a passcode via SMS so that user can do an MFA login"""
    session = requests.Session()
    soup = BeautifulSoup(password_login_response.text, "html.parser")
    cookie_dict = {}
    cookie_dict['sid'] = password_login_response.cookies['sid']
    headers_dict = {}
    headers_dict['referer'] = password_login_response.url
    # Look for the _xsrfToken which we need for a header
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == '_xsrfToken'):
            xsrfToken = inputtag.get('value')
    headers_dict['X-Okta-Xsrftoken'] = xsrfToken
    send_sms_url = "https://{}/auth/sms/send".format(
                                urlparse(password_login_response.url).netloc)
    # POST to send_sms_url to have Okta send the SMS
    session.post(send_sms_url, headers=headers_dict, cookies=cookie_dict,
                 verify=True)

def update_config_file(okta_aws_login_config_file):
    """Prompts user for config details for the okta_aws_login tool.
    Either updates exisiting config file or creates new one."""
    config = configparser.ConfigParser()
    # See if a config file already exists.
    # If so, use current values as defaults
    if os.path.isfile(okta_aws_login_config_file) == True:
        config.read(okta_aws_login_config_file)
        idp_entry_url_default = config['DEFAULT']['idp_entry_url']
        region_default = config['DEFAULT']['region']
        output_format_default = config['DEFAULT']['output_format']
        cache_sid_default = config['DEFAULT']['cache_sid']
        cred_profile_default = config['DEFAULT']['cred_profile']
    # otherwise use these values for defaults
    else:
        idp_entry_url_default = ""
        region_default = ""
        output_format_default = "json"
        cache_sid_default = "yes"
        cred_profile_default = "role"
    # Prompt user for config details and store in config_dict
    config_dict = {}
    # Get and validate idp_entry_url
    print("Enter the IDP Entry URL. This is the EMBED LINK URL found on the "
            "General tab of the Okta AWS App.")
    idp_entry_url_valid = False
    while idp_entry_url_valid == False:
        idp_entry_url =  get_user_input("idp_entry_url",idp_entry_url_default)
        # Validate that idp_entry_url is a well formed okta URL
        url_parse_results = urlparse(idp_entry_url)
        if (url_parse_results.scheme == "https" and
                                     "okta.com" in idp_entry_url):
            idp_entry_url_valid = True
        else:
            print("idp_entry_url must be HTTPS URL for okta.com domain")
    config_dict['idp_entry_url'] = idp_entry_url
    # Get and validate region
    print("Enter the default region that will be used by the okta_aws_login "
            "tool and configured as part of the CLI profile.")
    aws_regions = ["us-east-1","us-east-2","us-west-1","us-west-2","eu-west-1",
                    "eu-central-1","ap-southeast-1","ap-southeast-2",
                    "ap-northeast-1","sa-east-1"]
    region_valid = False
    while region_valid == False:
        region = get_user_input("region",region_default)
        # validate entered region is valid AWS region
        if region in aws_regions:
            region_valid = True
        else:
            print("region must be valid AWS region: {}".format(aws_regions))
    config_dict['region'] = region
    # Get and validate output_format
    print("Enter the default output format that will be configured as part of "
            "CLI profile")
    valid_formats = ["json","text","table"]
    output_format_valid = False
    while output_format_valid == False:
        output_format = get_user_input("output_format",output_format_default)
        # validate entered region is valid AWS CLI output format
        if output_format in valid_formats:
            output_format_valid = True
        else:
            print("output format must be a valid format: {}".format(
                                                            valid_formats))
    config_dict['output_format'] = output_format
    # Get and validate cache_sid
    print("cache_sid determines if the session id from Okta should be saved "
            "to a local file. If enabled it allows for new tokens to be "
            "retrieved without a login to Okta for the lifetime of the "
            "session. Either 'yes' or 'no'")
    cache_sid_valid = False
    while cache_sid_valid == False:
        cache_sid = get_user_input("cache_sid",cache_sid_default)
        cache_sid = cache_sid.lower()
        # validate if either true or false were entered
        if cache_sid in ["yes","y"]:
            cache_sid = "yes"
            cache_sid_valid = True
        elif cache_sid in ["no","n"]:
            cache_sid = "no"
            cache_sid_valid = True
        else:
            print("cache_sid must be either yes or no")
    config_dict['cache_sid'] = cache_sid
    # Get and validate cred_profile
    print("cred_profile defines which profile is used to store the temp AWS "
            "creds. If set to 'role' then a new profile will be created "
            "matching the role name assumed by the user. If set to 'default' "
            "then the temp creds will be stored in the default profile")
    cred_profile_valid = False
    while cred_profile_valid == False:
        cred_profile = get_user_input("cred_profile",cred_profile_default)
        cred_profile = cred_profile.lower()
        # validate if either role or default was entered
        if cred_profile in ["default","role"]:
            cred_profile_valid = True
        else:
            print("cred_profile must be either default or role")
    config_dict['cred_profile'] = cred_profile
    # Set default config
    config['DEFAULT'] = config_dict
    with open(okta_aws_login_config_file, 'w') as configfile:
        config.write(configfile)

def write_aws_creds(aws_config_file,profile,access_key,secret_key,token,
                    region,output):
    """ Writes the AWS STS token into the AWS credential file"""
    # Check to see if the aws creds path exists, if not create it
    creds_dir = os.path.dirname(aws_config_file)
    if os.path.exists(creds_dir) == False:
       os.makedirs(creds_dir) 
    config = configparser.RawConfigParser()
    # Read in the existing config file if it exists
    if os.path.isfile(aws_config_file):
        config.read(aws_config_file)
    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'output', output)
    config.set(profile, 'region', region)
    config.set(profile, 'aws_access_key_id', access_key)
    config.set(profile, 'aws_secret_access_key', secret_key)
    config.set(profile, 'aws_session_token', token)
    # Write the updated config file
    with open(aws_config_file, 'w+') as configfile:
        config.write(configfile)

def write_sid_file(sid_file,sid):
    """Writes a given sid to a file. Returns nothing"""
    sid_cache_file = os.open(sid_file,os.O_WRONLY|os.O_CREAT,mode=0o600)
    os.write(sid_cache_file,sid.encode())
    os.close(sid_cache_file)

def main():
    # Create/Update config when configure arg set
    if args.configure == True:
        update_config_file(okta_aws_login_config_file)
        sys.exit()
    # Check to see if config file exists, if not complain and exit
    # If config file does exist create config dict from file
    if os.path.isfile(okta_aws_login_config_file):
        config = configparser.ConfigParser()
        config.read(okta_aws_login_config_file)
        conf_dict = dict(config['DEFAULT'])
    else:
        print(".okta_aws_login_config is needed. Use --configure flag to "
                "generate file.")
        sys.exit(1)
    # declaring a var to hold the SAML assertion. 
    assertion = None
    # if sid cache is enabled, see if a sid file exists
    if conf_dict['cache_sid'] == "yes":
        sid = get_sid_from_file(sid_cache_file)
    else:
        sid = None
    # If a sid has been set from file then attempt login via the sid
    if sid is not None:
        response = okta_cookie_login(sid,conf_dict['idp_entry_url'])
        assertion = get_saml_assertion(response)
    # if the assertion equals None, means there was no sid, the sid expired 
    # or is otherwise invalid, so do a password login
    if assertion is None:        
        # If sid file exists, remove it because the contained sid has expired
        if os.path.isfile(sid_cache_file):
            os.remove(sid_cache_file)
        user_creds = get_user_creds()
        response = okta_password_login(user_creds['username'],
                                       user_creds['password'],
                                       conf_dict['idp_entry_url'])
        assertion = get_saml_assertion(response)
    # If the assertion is still none after the password login, then something
    # is wrong, complain and exit 
    if assertion is None:
        print("No valid SAML assertion retrieved!")
        sys.exit(1)
    # If cache sid enabled write sid to file
    if conf_dict['cache_sid'] == "yes":
        write_sid_file(sid_cache_file,response.cookies['sid'])
    # Get arns from the assertion and the AWS creds from STS
    saml_dict = get_arns_from_assertion(assertion) 
    aws_creds = get_sts_token(saml_dict['RoleArn'],
                          saml_dict['PrincipalArn'],
                          saml_dict['SAMLAssertion'])
    # Get role name to use for the name of the profile
    # check if profile arg has been set
    if args.profile is not None:
        profile_name = args.profile
    # else check if profile should be default
    elif conf_dict['cred_profile'] == 'default':
        profile_name = 'default'
    # otherwise check to see if it should be the name of the role 
    elif conf_dict['cred_profile'] == 'role':
        profile_name = saml_dict['RoleArn'].split('/')[1]
    # if none complain and exit
    else:
        print("profile_name not set!")
        sys.exit()
    write_aws_creds(aws_config_file,
                    profile_name,
                    aws_creds['AccessKeyId'],
                    aws_creds['SecretAccessKey'],
                    aws_creds['SessionToken'],
                    conf_dict['region'],
                    conf_dict['output_format'])

    # Print message about aws_creds if verbose is set
    if args.verbose == True:
        now = datetime.now(timezone.utc)
        valid_duration = aws_creds['Expiration'] - now
        valid_minutes = math.ceil(valid_duration / timedelta(minutes=1)) 
        cred_details = ("Credentials for the profile {} have been set. "
                        "They will expire in {} minutes.".format(profile_name,
                        valid_minutes)) 
        print(cred_details)

if __name__ == '__main__':
    main()


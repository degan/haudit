import sys,argparse,urllib 

print("haudit (https://github.com/degan/haudit)")

parser = argparse.ArgumentParser(description='HTTP Header Audit')
parser.add_argument('url', help='URL to check')
args = parser.parse_args()

http_audit = {'X-XSS-Protection' : 'Enables the Cross-site scripting filter built into browsers.','X-Frame-Options' : 'Enables Clickjacking prevention.','Strict-Transport-Security' : 'HSTS Enforces secure SSL connections. Only enable if entire domain is SSL. Subdomains can be included as well.','X-Content-Type-Options' : 'Prevents MIME-sniffing.','Content-Security-Policy' : 'Attack Prevention.', 'X-Download-Options' : 'Prevent downloads from opening automatically, etc', 'Access-Control-Allow-Origin' : 'Restrict data and content from your site', 'Public-Key-Pins' : 'HPKP'}
#TODO: https specific checks
https_audit = {'Set-Cookie' : 'cookie should be secure and httponly over SSL.', 'Cache-Control' : ''}

try: 
    if "https" in args.url:
        https = True;
    else:
        https = False;

    print ("")
    headers = urllib.urlopen(args.url).headers.headers
    headers_split = {}
    headers_split_upper = {}
    for header in headers:
        header = header.split(':')
        headers_split[header[0]] = header[1]
        headers_split_upper[header[0].upper()] = header[1]

    print ("Audit Headers")
    item_num = 0 
    for item in http_audit:
        if item.upper() in headers_split_upper:
            item_num = item_num + 1
            item_value = headers_split_upper[item.upper()].strip() 
            print (str(item_num) + ". " + item + ": " + item_value)  
            item = item.upper()
            item_value = item_value.upper()

            if item == "X-XSS-PROTECTION":
                #TODO: validate report url if included
                if item_value == "0" or item_value == "1" or item_value == "1; MODE=BLOCK" or item_value == "1; REPORT=HTTP": 
                    print ("Valid!\n")
                else:
                    print ("***ERROR***\n")
            if item == "X-FRAME-OPTIONS":
                #TODO: validate url if included
                if item_value == "DENY" or item_value == "SAMEORIGIN" or item_value == "ALLOW-FROM HTTP":
                    print ("Valid!\n")
                else:
                    print ("***ERROR***\n")
            if item == "STRICT-TRANSPORT-SECURITY":
                #TODO: smarter validation
                if "MAX-AGE=" in item_value:
                    print ("Valid!\n")
                else:
                    print ("***ERROR***\n");
            if item == "X-CONTENT-TYPE-OPTIONS":
                if item_value == "NOSNIFF":
                    print ("Valid!\n")
                else:
                    print ("***ERROR***\n")
            if item == "CONTENT-SECURITY-POLICY":
                #TODO
                print ("Valid!\n")

    print ("\nMissing Headers")
    item_num = 0 
    for item in http_audit:
        if item.upper() not in map(str.upper, headers_split):
            item_num = item_num + 1
            print (str(item_num) + ". " + item + " (" + http_audit[item] + ")\n")

except urllib.HTTPError as e:
    print ("HTTP Error: " + str(e.code) + " - " + str(e.reason))

except urllib.URLError as e:
    print ("URL Error: " +  str(e.reason))

except ValueError as e:
    print ("URL Error: " + str(e))

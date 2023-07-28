# This script takes an input file and locates all information that the user may want to redact.
# Redactable information is: Email addresses, api keys, ip addresses, phone numbers, and names.

import re
import sys

# This function takes a file and returns a list of all the lines in the file.
def get_file_lines(file):
    with open(file) as f:
        lines = f.readlines()
    return lines

def addToSecrets(value, type):
    #write value to secrets.csv in type, value format
    with open('secrets.csv', 'a') as f:
        # if secrets.csv isn't empty, add a newline
        if f.tell() != 0:
            f.write('\n')
        f.write(type + ',' + value)
    
def addToIgnore(value, type):
    #write value to ignore.csv in type, value format
    with open('ignore.csv', 'a') as f:
        if f.tell() != 0:
            f.write('\n')
        f.write(type + ',' + value)

def askUser(value, type):
    print("Found a potential " + type + ": " + str(value))
    print("Would you like to redact? (yes/no/always/never)")
    while True:
        answer = input()
        if answer == 'yes' or answer == 'y':
            return True
        elif answer == 'no' or answer == 'n':
            return False
        elif answer == 'always' or answer == 'a':
            addToSecrets(value, type)
            return True
        elif answer == 'never':
            addToIgnore(value, type)
            return False

def getSecretLists():
    # Import the secrets.csv and parse it to get the Emails, IPs, etc to be redacted
    # First Column is the data type, second is the value
    with open('secrets.csv') as f:
        lines = f.readlines()
    emails = []
    ips = []
    phones = []
    names = []
    apis = []
    for line in lines:
        line = line.split(',')
        #remove newline character from end of value
        line[1] = line[1].rstrip()
        if line[0] == 'email':
            emails.append(line[1])
        elif line[0] == 'ip':
            ips.append(line[1])
        elif line[0] == 'phone':
            phones.append(line[1])
        elif line[0] == 'name':
            names.append(line[1])
        elif line[0] == 'api':
            apis.append(line[1])
    if len(emails) > 0:
        print("Emails to redact: " + str(emails))
    if len(ips) > 0:
        print("IPs to redact: " + str(ips))
    if len(phones) > 0:
        print("Phones to redact: " + str(phones))
    if len(names) > 0:
        print("Names to redact: " + str(names))
    if len(apis) > 0:
        print("APIs to redact: " + str(apis))
    return emails, ips, phones, names, apis

def getIgnoreLists():
    # Import the secrets.csv and parse it to get the Emails, IPs, etc to be redacted
    # First Column is the data type, second is the value
    with open('ignore.csv') as f:
        lines = f.readlines()
    emails_ignore = []
    ips_ignore = []
    phones_ignore = []
    names_ignore = []
    apis_ignore = []
    for line in lines:
        line = line.split(',')
        #remove newline character from end of value
        line[1] = line[1].rstrip()
        if line[0] == 'email':
            emails_ignore.append(line[1])
        elif line[0] == 'ip':
            ips_ignore.append(line[1])
        elif line[0] == 'phone':
            phones_ignore.append(line[1])
        elif line[0] == 'name':
            names_ignore.append(line[1])
        elif line[0] == 'api':
            apis_ignore.append(line[1])
    if len(emails_ignore) > 0:
        print("Emails to ignore: " + str(emails_ignore))
    if len(ips_ignore) > 0:
        print("IPs to ignore: " + str(ips_ignore))
    if len(phones_ignore) > 0:
        print("Phones to ignore: " + str(phones_ignore))
    if len(names_ignore) > 0:
        print("Names to ignore: " + str(names_ignore))
    if len(apis_ignore) > 0:
        print("APIs to ignore: " + str(apis_ignore))
    return emails_ignore, ips_ignore, phones_ignore, names_ignore, apis_ignore

    
def redact(line,secretArray,ignoreArray,type,interactive,pattern=None):
    # If part of the line matches any element of array, replace that part of the line with the type of redaction
    for value in secretArray:
        if value in line:
            return re.sub(value, str(type).upper() + '_REDACTED', line), secretArray, ignoreArray
    if interactive and pattern:
        #print("Checking " + line +" for " + type+ "s")
        value=re.search(pattern, line)
        if value:
            value=value.group(0)
            if value not in ignoreArray and askUser(value, type):
                secretArray.append(value)
                return re.sub(value, str(type).upper() + '_REDACTED', line), secretArray, ignoreArray
            else:
                ignoreArray.append(value)
                return line, secretArray, ignoreArray
        else:
            return line, secretArray, ignoreArray
    else:
        return line, secretArray, ignoreArray
    
def redactAPI(line,secretArray,ignoreArray,type,interactive):
    apiStrings=['token=','key=','api=','apikey=','apitoken=','apitok=','apitokn=','apitokne=','apitokn=','apitok=','apito=','apit=','api=','ap=','a=']
    # If part of the line matches any element of array, replace that part of the line with the type of redaction
    for value in secretArray:
        if value in line:
            return re.sub(value, str(type).upper() + '_REDACTED', line), secretArray, ignoreArray
    if interactive:
        for apiString in apiStrings:
            if apiString in line:
                # remove the string after the api string but before the & or space
                value=re.search(apiString + '[^&\s]*', line)
                if value:
                    value=value.group(0)
                    #remove the api string from the value
                    value=value.replace(apiString,'')
                    if value not in ignoreArray and askUser(value, type):
                        secretArray.append(value)   
                        return re.sub(value, apiString + str(type).upper() + '_REDACTED', line), secretArray, ignoreArray                    
                    else:
                        ignoreArray.append(value)
        return line, secretArray, ignoreArray
        

# This function takes a list of lines and returns a list of all the lines that contain redactable information.
def parse(lines, interactive):
    emails, ips, phones, names, apis = getSecretLists()
    emails_ignore, ips_ignore, phones_ignore, names_ignore, apis_ignore = getIgnoreLists()
    stripped_lines = []
    for line in lines:
        line, emails, emails_ignore=redact(line, emails, emails_ignore,'email', interactive, r'[\w\.-]+@[\w\.-]+')
        line, ips, ips_ignore=redact(line, ips, ips_ignore, 'ip', interactive, r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        line, phones, phones_ignore=redact(line, phones, phones_ignore, 'phone', interactive, r'\d{3}-\d{3}-\d{4}')
        line, names, names_ignore=redact(line, names, names_ignore, 'name', interactive)
        #no great way to find an api key, so look for key= and redact the next word
        line, apis, apis_ignore=redactAPI(line, apis, apis_ignore, 'api', interactive)
        stripped_lines.append(line)
    return stripped_lines

def main():
    interactive=False
    # if argument is specified, use that file, otherwise ask user
    if len(sys.argv) > 1:
        file = sys.argv[1]
    else:
        print("Please enter the name of the file you would like to redact:")
        file = input()
    print("Redacting " + file)
    # if 2 arguments were specified, check if second is -i
    if len(sys.argv) > 2 and sys.argv[2] == '-i':
        print("Running in interactive mode")
        interactive = True
    lines = get_file_lines(file)
    stripped_lines = parse(lines, interactive)
    with open(file + '-redacted', 'w') as f:
        for line in stripped_lines:
            f.write(line)
    print("Redacted file saved as " + file + "-redacted")

#run the main function
if __name__ == "__main__":
    main()
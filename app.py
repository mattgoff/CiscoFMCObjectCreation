from getpass import getpass
from io import DEFAULT_BUFFER_SIZE

import json
import requests
from requests.models import HTTPBasicAuth

resultsDictionary = {}

def parseTextFile():
    with open("data.txt", "r") as f:
        file_data = f.readlines()
        for line in file_data:
            line_split_up = line.split("DstIP: ")
            part_two_split = line_split_up[1].split(",")
            DestIP = part_two_split[0]
            
            DestPort = part_two_split[2]
            # DestPort = DestPort.split(": ")[1]
            DestPort = DestPort.replace(" DstPort: ", "")

            if DestIP in resultsDictionary:
                resultsDictionary[DestIP][0] += 1    
            else:
                resultsDictionary[DestIP] = []
                resultsDictionary[DestIP].append(1)
                resultsDictionary[DestIP].append(DestPort)

def goGetAAuthToken():
    username = "mgoff"
    password = getpass("Enter password for Mgoff: ")
    url = "https://10.200.25.29/api/fmc_platform/v1/auth/generatetoken"

    payload={}
    headers = {'Authorization': 'Basic xxxxxxxxxxxxxxxx'}

    # response = requests.request("POST", url, verify=False, headers=headers, data=payload)

    response = requests.post(url, verify=False, auth=HTTPBasicAuth(username, password))

    authToken = response.headers['X-auth-access-token']
    print(authToken)

    return authToken


def logout(xAuthToken):
    '''
    Used for explicit session logout
    '''
    logout_payload = {'grant_type': 'revoke_token',
                        'access_token': xAuthToken,
                        'token_to_revoke': xAuthToken}

    # requests.post("https://{}:{}/api/fmc_platform/v1/auth/token".format(self.server_address, self.server_port),
    #                 data=json.dumps(logout_payload), verify=False, headers=FTDClient.headers)


def createNewHostObject(xAuthToken, IPofNewObject):
    url = "https://10.200.25.29/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts"

    payload = json.dumps({
        "type": "Host",
        "value": IPofNewObject,
        "overridable": False,
        "description": " ",
        "name": f'EllieMae-{IPofNewObject}'
        })
    headers = {
        'X-auth-access-token': xAuthToken,
        'Content-Type': 'application/json'
        }

    response = requests.request("POST", url, verify=False, headers=headers, data=payload)

    if response.status_code == 201:
        newID = response.json()['id']
    else:
        newID = response.json()['error']['messages'][0]['description']

    return response.status_code, newID

def whoOwnsThisIP():
    counter = 1
    with open('results.txt', "w+") as file:
        for IP in resultsDictionary:
            newURL = "http://ipwhois.app/json/{}".format(IP)
            data = requests.get(newURL).json()
            # print("{} {} {}".format(counter, IP, data['org']))
            file.write("{} {} {}\n".format(counter, IP, data['org']))
            counter += 1

parseTextFile()
xAuthToken = goGetAAuthToken()
# whoOwnsThisIP()

for IPAddress in resultsDictionary:
    addResult, newID = createNewHostObject(xAuthToken, IPAddress)
    print("Adding: {} Result: {}  NewUID: {}".format(IPAddress, addResult, newID))
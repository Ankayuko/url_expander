import requests
import click
import logging
import json
import concurrent.futures

# Read the url list from a file and return it
def read_file(filename):
    url_list = list()
    try:
        with open(filename) as f:
            for line in f:
                url_list.append(line.strip())
            f.close()
    except FileNotFoundError as e:
        logging.warning(e)
        exit()
    return url_list

# Send a get request and extract the location in the response history headers (which coincides with the expanded link)
def url_expand(url):
    responses = list()
    responses.append(requests.get(url))

    expanded_urls = dict()
    for response in responses:
        if response.history:
            for element in response.history:
                if element.headers['Location']:
                    expanded_urls[element.url] = element.headers['Location']
        else:
            continue
    return expanded_urls


logging.basicConfig(level=logging.INFO)
url_list = list()
url_list = read_file('url_list.txt')

expanded_urls = dict()
with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = list()
    for url in url_list:
        futures.append(executor.submit(url_expand, url=url))
    for future in concurrent.futures.as_completed(futures):
        expanded_urls.update(future.result())
        logging.info(future.result())

my_list = list(expanded_urls.values())

api_key=''
url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

f = open('payload.json', 'r+')
payload = json.load(f)
payload['threatInfo']['threatEntries'].clear()

for value in expanded_urls.values():
    to_write = {"url": value}
    payload['threatInfo']['threatEntries'].append(to_write)

f.seek(0)
json.dump(payload, f, indent = 4)
f.close()

f = open('payload.json')
payload = json.load(f)
f.close()
params = {'key': api_key}
r = requests.post(url, params=params, json=payload)

for values in r.json().values():
    for value in values:
        print('\n' + value['threat']['url'] + ' ----------> ' + value['threatType'])

"""
Aung Phyo
06/10/2018
following coding can scan the file for threat check
using the metadefender API from https://portal.opswat.com/

"""
import json
import requests
import sys
from py_essentials import hashing as hs

#calculating hash of the file
hash256 = hs.fileChecksum(sys.argv[1],"sha256");

hash1 = hs.fileChecksum(sys.argv[1],"sha1");

hashMD5 = hs.fileChecksum(sys.argv[1],"md5");

#using the hash to create the url
url = "https://api.metadefender.com/v2/hash/" + str(hash1)

headers = {
'apikey': "API_KEY",
'file-metadata' : "1"
}

#request the url and create the json object
response = requests.get(url, headers=headers).json()

#call the key and get the value
for r in response:
    dataid = response[r]

#if the data_id is not found then upload the file
#after uploading call the API with data_id
if  dataid == 'Not Found':

    data = open(sys.argv[1], 'rb').read()
    response1 = requests.post('https://api.metadefender.com/v2/file', headers=headers, data=data)
    bts = response1.text
    dstring = dict()
    for item in bts.split(','):
        pair = item.split(':')
        dstring.update({pair[0]: pair[1][1:-1]})

    response2 = requests.get('https://api.metadefender.com/v2/file/' + str(dstring['{"data_id"']), headers=headers).json()

    #checking the upload file is 100 percent scanned
    while response2['scan_results']['progress_percentage'] != 100:
        response2 = requests.get('https://api.metadefender.com/v2/file/' + str(dstring['{"data_id"']), headers=headers).json()
        if response2['scan_results']['progress_percentage'] == 100:
            continue

    sfile2 = response2['file_info']
    filename2 = sfile2['display_name']
    print()
    print("Output: ")
    print()
    print("filename: " + filename2)

    data2 =  response2['scan_results']
    detail2 = data2['scan_details']
    result2 = data2['scan_all_result_a']
    print("overall_status: " + result2)
    print()


    for fact in detail2:
        print("engine: " + fact)
        print("threat_found: " + detail2[fact]['threat_found'])
        print("scan_result: " + str(detail2[fact]['scan_result_i']))
        print("def_time: " + detail2[fact]['def_time'])
        print()

#if the file was uploaded before then print all
else:
    sfile = response['file_info']
    filename = sfile['display_name']
    print()
    print("Output: ")
    print()
    print("filename: " + filename)

    data =  response['scan_results']
    detail = data['scan_details']
    result = data['scan_all_result_a']
    print("overall_status: " + result)
    print()

    for fact in detail:
        print("engine: " + fact)
        print("threat_found: " + detail[fact]['threat_found'])
        print("scan_result: " + str(detail[fact]['scan_result_i']))
        print("def_time: " + detail[fact]['def_time'])
        print()

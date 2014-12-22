import simplejson
import urllib
import urllib2
import csv
import time

antiviruses = [
	'Bkav',
	'MicroWorld-eScan',
	'nProtect',
	'CMC',
	'CAT-QuickHeal',
	'McAfee',
	'Malwarebytes',
	'VIPRE',
	'AegisLab',
	'TheHacker',
	'K7GW',
	'K7AntiVirus',
	'NANO-Antivirus',
	'F-Prot',
	'Symantec',
	'Norman',
	'TotalDefense',
	'TrendMicro-HouseCall',
	'Avast',
	'ClamAV',
	'Kaspersky',
	'BitDefender',
	'Agnitum',
	'SUPERAntiSpyware',
	'ByteHero',
	'Rising',
	'Ad-Aware',
	'Emsisoft',
	'Comodo',
	'F-Secure',
	'DrWeb',
	'Zillya',
	'TrendMicro',
	'McAfee-GW-Edition',
	'Sophos',
	'Cyren',
	'Jiangmin',
	'Avira',
	'Antiy-AVL',
	'Kingsoft',
	'Microsoft',
	'ViRobot',
	'GData',
	'AhnLab-V3',
	'VBA32',
	'AVware',
	'Panda',
	'Zoner',
	'ESET-NOD32',
	'Tencent',
	'Ikarus',
	'Fortinet',
	'AVG',
	'Baidu-International',
	'Qihoo-360'
]

suspicious = False
counter = 0
malicious_counter = 0
time_to_sleep = 61
url = "https://www.virustotal.com/vtapi/v2/file/report"

f = open('rest.csv')
try:
    reader = csv.reader(f)
    for row in reader:
    	parameters = {"resource": row[1], "apikey": sys.argv[1]}
    	data = urllib.urlencode(parameters)
    	req = urllib2.Request(url, data)
    	response = urllib2.urlopen(req)
    	json = response.read()
    	response_dict = simplejson.loads(json)

    	for i in range(0, len(antiviruses)):
    		if response_dict.get("scans", {}).get(antiviruses[i], {}).get("detected") == True:
    			suspicious = True
    			print row[0]
    			print antiviruses[i]
    			print response_dict.get("scans", {}).get(antiviruses[i], {})
    			print response_dict.get("scans", {}).get(antiviruses[i], {}).get("result")

    	if suspicious == True:
    		malicious_counter = malicious_counter + 1
    		print malicious_counter

    	suspicious = False
    	if(counter == 3):
    		time.sleep(time_to_sleep)
    		counter = -1
    	counter = counter + 1
finally:
    f.close()


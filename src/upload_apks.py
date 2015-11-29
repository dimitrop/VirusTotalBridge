/*
 * Copyright 2015 Dimitrios Mitropoulos
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

import csv
import urllib2
import formdata
import time

temp = ''
time_to_sleep = 61
fields = {'apikey': sys.argv[1]}
counter = 0

f = open('md5sums_rest.csv')
try:
    reader = csv.reader(f)
    for row in reader:
    	tmp = row[0]
    	print(tmp)

    	with open(tmp, mode='rb') as f:
    		file_to_send = f.read()
    	files = {'file': {'filename': tmp, 'content': file_to_send}}
    	data, headers = formdata.encode_multipart(fields, files)
    	request = urllib2.Request('https://www.virustotal.com/vtapi/v2/file/scan', data=data, headers=headers)
    	try:
            f = urllib2.urlopen(request)
            print f.read()
        except:
            with open("large_ones_not_up.csv", "a") as myfile:
                myfile.write(row[0]+","+row[1]+"\n")
            print("Failed: The file is too large.")
            pass

    	if(counter == 3):
    		time.sleep(time_to_sleep)
    		counter = -1
    	counter = counter + 1
finally:
    f.close()

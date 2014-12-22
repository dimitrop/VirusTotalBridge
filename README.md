These Python scripts were created to automatically check if **multiple** apks are malicious by uploading them on the [VirusTotal](https://www.virustotal.com/) website.This requires two steps: 1) upload them (__upload_apks.py__), and 2) check the reports (__retrieve_reports.py__).

To upload the apks the former script requires a csv that contains the names of the apks together with their MD5s (VirusTotal identifies apks through their MD5). In our case it's __md5sums.csv__ --- hardcoded (doh! :-P). You also need to have the apks in the same directory. The same csv can be used to retrieve the results by the latter script.

In addition, to perform massive requests from VirusTotal you need to register and get a Publik API key which you must provide as an argument in all the scripts.

The script "__check_apk.py__" can be used to check the results for one given apk. Usage:

> check_apk.py vercoop.bautifulch.app-116.apk __your_API_key__

Note that VirusTotal does not accept upload requests (via its [Public API](https://www.virustotal.com/en/documentation/public-api/)) for large apks (> 32 MB). In such cases we register which files were not uploaded in another .csv file (__large_ones_not_up.csv__).

Finally, we use the formdata script that encodes multipart form data to upload files via POST requests, and it was obtaind from [here](http://code.activestate.com/recipes/578668-encode-multipart-form-data-for-uploading-files-via/).
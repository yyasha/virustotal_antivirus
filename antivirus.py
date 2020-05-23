from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import os
import time
import shutil
import plyer
from pathlib import Path

API_KEY = 'Sign-Up for API Key at virustotal.com'  #your API key

directory = 'the directory where the scan takes place' #C:/Users/
directoryTo = 'the directory to move after the scan'

sleep = 10

lastLen = 0

try:

	while True:
		time.sleep(sleep)

		if lastLen != len(os.listdir(path=directory)):

			lastLen = 0

			for i in os.listdir(path=directory):
				filename = f'{directory}/{i}'

				if Path(i).suffix == '.crdownload':
					continue

				with open(filename, 'rb') as f:
					m = hashlib.md5()
					while True:
						data = f.read(8192)
						if not data:
							break
						m.update(data)

				vt = VirusTotalPublicApi(API_KEY)

				response = vt.get_file_report(m.hexdigest())
				pull = json.loads(json.dumps(response, sort_keys=False, indent=4))
				results = pull["results"]
				try:
					detected = results["positives"]
					if detected > 0:
						os.remove(filename)
						plyer.notification.notify( message=f"В файле {i} обнаружен вирус ({detected}), файл будет удалён", app_name='VirusTotal', app_icon='icon.ico', title='VirusTotal', )
						detected = 0
				except Exception as e:
					shutil.move(filename, directoryTo)

except Exception as e:
	raise

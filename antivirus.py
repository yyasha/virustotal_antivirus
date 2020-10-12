from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import os
import time
import shutil
import plyer
from pathlib import Path

API_KEY = 'Sign-Up for API Key at virustotal.com'

directory = 'C:/Users/user/Downloads/antivirus/detecter' #C:/Users/
directoryTo = 'C:/Users/user/Downloads'
directoryPhotos = 'C:/Users/user/Downloads/Photos'
directoryDocuments = 'C:/Users/user/Downloads/Documents'
directoryMusic = 'C:/Users/user/Downloads/Music'
directoryVideos = 'C:/Users/user/Downloads/Videos'

PhotosExtension = ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff']
DocumentsExtension = ['.pdf', '.doc', '.pptx', '.txt', '.rtf', '.docx', '.xls', '.xlsx', '.xlsm', '.ods']
MusicExtension = ['.mp3', '.wav', '.wma']
VideosExtension = ['.mp4', '.avi', '.wmf']

Moved = False

sleepT = 1

lastLen = 0

try:

	while True:
		time.sleep(sleepT)

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

				try:
					results = pull["results"]
				except Exception as e:
					time.sleep(10)
					continue

				try:
					detected = results["positives"]
				except Exception as e:
					detected = 0

				if detected > 0:
					os.remove(filename)
					plyer.notification.notify( message=f"В файле {i} обнаружен вирус ({detected}), файл будет удалён", app_name='VirusTotal', app_icon='icon.ico', title='VirusTotal', )
					detected = 0
					Moved = True

				if Moved == False:
					for ex in PhotosExtension:
						if Path(i).suffix == ex:
							shutil.move(filename, directoryPhotos)
							Moved = True
							break

				if Moved == False:
					for ex in DocumentsExtension:
						if Path(i).suffix == ex:
							shutil.move(filename, directoryDocuments)
							Moved = True
							break

				if Moved == False:
					for ex in MusicExtension:
						if Path(i).suffix == ex:
							shutil.move(filename, directoryMusic)
							Moved = True
							break

				if Moved == False:
					for ex in VideosExtension:
						if Path(i).suffix == ex:
							shutil.move(filename, directoryVideos)
							Moved = True
							break

				if Moved == False:
					shutil.move(filename, directoryTo)

except Exception as e:
	raise

import requests
import json
import os

API_KEY = '512a7e5a3c9aa1dd8c9e7236125194a499153e5a7110b4a3d0b73450f692279f'
BASE_URL = 'https://www.virustotal.com/api/v3'
headers = {
    'x-apikey': API_KEY
}

# Сканирование файла

file_path = 'test.txt'  

if not os.path.exists(file_path):
    print(f" Файл не найден: {file_path}")
else:
    print(f" Загрузка файла {file_path} для анализа...")
    upload_url = f"{BASE_URL}/files/upload_url"
    response = requests.get(upload_url, headers=headers)

    if response.status_code != 200:
        print(f"Ошибка получения URL для загрузки: {response.status_code} — {response.text}")
    else:
        upload_url = response.json()['data']

        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(upload_url, headers=headers, files=files)

        if response.status_code == 200:
            result = response.json()
            file_id = result['data']['id']
            print(f"Файл успешно загружен. ID анализа: {file_id}")

            analysis_url = f"{BASE_URL}/analyses/{file_id}"
            print("Ожидание завершения анализа... (может занять время)")

            import time
            while True:
                response = requests.get(analysis_url, headers=headers)
                if response.status_code == 200:
                    report = response.json()
                    status = report['data']['attributes']['status']
                    if status == 'completed':
                        stats = report['data']['attributes']['stats']
                        print("Результаты анализа файла:")
                        print(json.dumps(stats, indent=2))
                        break
                    elif status == 'queued' or status == 'in-progress':
                        print("Анализ ещё в очереди или выполняется... Ждём 10 секунд.")
                        time.sleep(10)
                    else:
                        print(f"Неизвестный статус: {status}")
                        break
                else:
                    print(f"Ошибка при получении отчёта: {response.status_code}")
                    break
        else:
            print(f"Ошибка загрузки файла: {response.status_code} — {response.text}")

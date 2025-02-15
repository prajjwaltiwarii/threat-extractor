import requests

url = "http://localhost:8000/upload_pdf/"
files = {"file": open("sample.pdf", "rb")}
response = requests.post(url, files=files)
print(response.json())

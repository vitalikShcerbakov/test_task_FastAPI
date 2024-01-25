import json

import requests
from requests.auth import HTTPBasicAuth

USERNAME = "johndoe"
PASSWORD = "secret"


def get_token():
    token_url = "http://localhost:8000/token"
    auth = HTTPBasicAuth(username=USERNAME, password=PASSWORD)
    data = {
        "grant_type": "password",
        "username": USERNAME,
        "password": PASSWORD,
    }
    response = requests.post(token_url, auth=auth, data=data)
    return response.json().get("access_token")


def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(10):
        requests.post(
            'http://127.0.0.1:8000/item/',
            data=json.dumps(
                {'value': f'test_client {i}'}
            ), headers=headers)

    response = requests.get('http://127.0.0.1:8000/items/', headers=headers)
    print(response.text)


if __name__ == '__main__':
    main()

import requests
import json


def main():
    for i in range(10):
        requests.post(
            'http://127.0.0.1:8000/item/',
            data=json.dumps(
                {'value': f'test_client {i}'}
            ))

    response = requests.get('http://127.0.0.1:8000/items/')
    print(response.text)


if __name__ == '__main__':
    main()

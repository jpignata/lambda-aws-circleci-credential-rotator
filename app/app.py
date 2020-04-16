import boto3
import json
import os
import requests
from typing import List, Tuple

CIRCLECI_TOKEN_KEY = 'circle-token'
CIRCLECI_BASE_URL = 'https://circleci.com/api/v2/project'

iam = boto3.client('iam')
secretsmanager = boto3.client('secretsmanager')


def handler(event, context):
    username = os.environ.get('IAM_USERNAME')
    repo = os.environ.get('REPO')
    circleci_config_secret = os.environ.get('CIRCLECI_CONFIG_SECRET')

    access_key_ids = list_access_key_ids(username)
    access_key_id, secret_access_key = create_access_key(username)
    circleci_token = get_secret_value(circleci_config_secret,
                                      CIRCLECI_TOKEN_KEY)

    try:
        update_env_var('AWS_ACCESS_KEY_ID', access_key_id, repo,
                       circleci_token)
        update_env_var('AWS_SECRET_ACCESS_KEY', secret_access_key, repo,
                       circleci_token)
    except RuntimeError:
        iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)
        raise

    for access_key_id in access_key_ids:
        iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)


def list_access_key_ids(username: str) -> List[str]:
    response = iam.list_access_keys(UserName=username)

    return [key['AccessKeyId'] for key in response['AccessKeyMetadata']]


def create_access_key(username: str) -> Tuple[str, str]:
    response = iam.create_access_key(UserName=username)
    access_key_id = response['AccessKey']['AccessKeyId']
    secret_access_key = response['AccessKey']['SecretAccessKey']

    return (access_key_id, secret_access_key)


def get_secret_value(key: str, subkey: str) -> str:
    response = secretsmanager.get_secret_value(SecretId=key)
    config = json.loads(response['SecretString'])

    return config[subkey]


def update_env_var(key: str, value: str, repo: str, token: str) -> None:
    headers = {'Circle-Token': token}
    payload = {'name': key, 'value': value}
    url = f'{CIRCLECI_BASE_URL}/{repo}/envvar?circle-token={token}'
    response = requests.post(url, json=payload, headers=headers)

    if response.status_code != 201:
        raise RuntimeError('Could not update environment variable ' +
                           f'status_code={response.status_code} ' +
                           f'body={response.content}')

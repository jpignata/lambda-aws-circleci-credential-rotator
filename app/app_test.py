import botocore.session
import json
import os
import unittest
from botocore.stub import Stubber
from datetime import datetime
from unittest.mock import patch, Mock, call

import app

# IAM materials for stubs. These are not real credentials, rather they are
# conventional examples used in AWS documentation. See https://bit.ly/2XsAkBq.
access_key_id = 'AKIAIOSFODNN7EXAMPLE'
secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY'
session_token = 'AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk' + \
                '4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTf' + \
                'lfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUp' + \
                'p2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HF' + \
                'vlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPP' + \
                'kUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr' + \
                '4rvx3iSIlTJabIQwj2ICCR/oLxBA=='
expiration = datetime(2015, 1, 1)

# Override app constants
app.IAM_USERNAME = 'username'
app.CIRCLECI_CONFIG_SECRET = 'shhh'
app.REPO = 'jpignata/thingie'
app.SESSION_DURATION_SECONDS = 900

# Clients
session = botocore.session.get_session()
iam = session.create_client('iam')
secretsmanager = session.create_client('secretsmanager')
sts = session.create_client('sts')


class TestApp(unittest.TestCase):
    @patch('app.requests.post')
    def test_handler_rotates_credentials(self, post):
        # Initializer stubbers
        iam_stubber = Stubber(iam)
        sts_stubber = Stubber(sts)
        secretsmanager_stubber = Stubber(secretsmanager)
        stubbers = [iam_stubber, sts_stubber, secretsmanager_stubber]
        # IAM stubs
        create_request = {'UserName': 'username'}
        create_response = {'AccessKey': {'UserName': 'username',
                                         'AccessKeyId': access_key_id,
                                         'Status': 'Active',
                                         'SecretAccessKey': secret_access_key}}
        delete_request = {'UserName': 'username',
                          'AccessKeyId': access_key_id}
        iam_stubber.add_response('create_access_key', create_response,
                                 create_request)
        iam_stubber.add_response('delete_access_key', {}, delete_request)
        # STS stub
        sts_request = {'DurationSeconds': 900}
        sts_response = {'Credentials': {'AccessKeyId': access_key_id,
                                        'SecretAccessKey': secret_access_key,
                                        'SessionToken': session_token,
                                        'Expiration': expiration}}
        sts_stubber.add_response('get_session_token', sts_response,
                                 sts_request)
        # SecretsManager stub
        request = {'SecretId': 'shhh'}
        response = {'SecretString': '{"circle-token":"SEKRET!"}'}
        secretsmanager_stubber.add_response('get_secret_value', response,
                                            request)
        # Requests stub
        post.return_value = Mock()
        post.return_value.status_code = 201

        for stubber in stubbers:
            stubber.activate()
        app.handler({}, {}, iam=iam, secretsmanager=secretsmanager, sts=sts)

        for stubber in stubbers:
            stubber.assert_no_pending_responses()
        url = 'https://circleci.com/api/v2/project/jpignata/thingie/envvar'
        header = {'Circle-Token': 'SEKRET!'}
        values = {'AWS_ACCESS_KEY_ID': access_key_id,
                  'AWS_SECRET_ACCESS_KEY': secret_access_key,
                  'AWS_SESSION_TOKEN': session_token}
        for i, (key, value) in enumerate(values.items()):
            json = {'name': key, 'value': value}
            expected = call(url, json=json, headers=header)
            self.assertEqual(post.mock_calls[i], expected)

    @patch('app.create_temporary_credentials')
    def test_handler_deletes_access_key_upon_exception(self, stub):
        stub.side_effect = Exception
        create_request = {'UserName': 'username'}
        create_response = {'AccessKey': {'UserName': 'username',
                                         'AccessKeyId': access_key_id,
                                         'Status': 'Active',
                                         'SecretAccessKey': secret_access_key}}
        delete_request = {'UserName': 'username',
                          'AccessKeyId': access_key_id}

        with Stubber(iam) as stubber:
            stubber.add_response('create_access_key', create_response,
                                 create_request)
            stubber.add_response('delete_access_key', {}, delete_request)

            with self.assertRaises(Exception):
                app.handler({}, {}, iam=iam)

            stubber.assert_no_pending_responses()

    def test_create_credentials_returns_credentials(self):
        request = {'UserName': 'username'}
        response = {'AccessKey': {'UserName': 'username',
                                  'AccessKeyId': access_key_id,
                                  'Status': 'Active',
                                  'SecretAccessKey': secret_access_key}}

        with Stubber(iam) as stubber:
            stubber.add_response('create_access_key', response, request)
            credentials = app.create_credentials('username', iam=iam)
            self.assertEqual(credentials, (access_key_id, secret_access_key))

    def test_retry_retries(self):
        self.retries = 0

        @app.retry(max_wait=0.001, log=False)
        def exercise():
            if self.retries == 1:
                return 'all good!'
            else:
                self.retries += 1
                raise RuntimeError('not good! not good at all!')

        self.assertEqual(exercise(), 'all good!')

    def test_retry_raises_exception_if_retried_max_attempts(self):
        self.retries = 0

        @app.retry(max_attempts=3, max_wait=0.001, log=False)
        def exercise():
            self.retries += 1
            raise RuntimeError

        with self.assertRaises(RuntimeError):
            exercise()

        self.assertEqual(self.retries, 3)

    def test_get_secrets_value_returns_secret_value(self):
        request = {'SecretId': 'key'}
        response = {'SecretString': '{"subkey":"SEKRET!"}'}

        with Stubber(secretsmanager) as stubber:
            stubber.add_response('get_secret_value', response, request)
            secret = app.get_secret_value('key', 'subkey',
                                          secretsmanager=secretsmanager)

            self.assertEqual(secret, 'SEKRET!')

    def test_get_secrets_value_with_missing_subkey_raises_keyerror(self):
        request = {'SecretId': 'key'}
        response = {'SecretString': '{}'}

        with Stubber(secretsmanager) as stubber:
            stubber.add_response('get_secret_value', response, request)

            with self.assertRaises(KeyError):
                app.get_secret_value('key', 'key',
                                     secretsmanager=secretsmanager)

    def test_get_secrets_value_with_missing_subkey_raises_jsonerror(self):
        request = {'SecretId': 'key'}
        response = {'SecretString': ''}

        with Stubber(secretsmanager) as stubber:
            stubber.add_response('get_secret_value', response, request)

            with self.assertRaises(json.decoder.JSONDecodeError):
                app.get_secret_value('key', 'key',
                                     secretsmanager=secretsmanager)

    def test_create_temporary_credentials_returns_temporary_credentials(self):
        request = {'DurationSeconds': 900}
        response = {'Credentials': {'AccessKeyId': access_key_id,
                                    'SecretAccessKey': secret_access_key,
                                    'SessionToken': session_token,
                                    'Expiration': expiration}}
        credentials = (access_key_id, secret_access_key)

        with Stubber(sts) as stubber:
            stubber.add_response('get_session_token', response, request)
            temp_credentials = app.create_temporary_credentials(credentials,
                                                                sts=sts)
            expected = {'AWS_ACCESS_KEY_ID': access_key_id,
                        'AWS_SECRET_ACCESS_KEY': secret_access_key,
                        'AWS_SESSION_TOKEN': session_token}
            self.assertEqual(temp_credentials, expected)

    @patch('app.requests.post')
    def test_update_envvars_posts_http_requests(self, post):
        temporary_credentials = {'AWS_ACCESS_KEY_ID': 'SOMETHINGIDK'}
        json = {'name': 'AWS_ACCESS_KEY_ID', 'value': 'SOMETHINGIDK'}
        headers = {'Circle-Token': 'token'}
        url = 'https://circleci.com/api/v2/project/jpignata/thingie/envvar'
        post.return_value = Mock()
        post.return_value.status_code = 201

        app.update_envvars(temporary_credentials, 'token', 'jpignata/thingie')

        self.assertEqual(post.call_args.args, ((url),))
        self.assertEqual(post.call_args.kwargs, {'json': json,
                                                 'headers': headers})

    def test_update_envvars_doesnt_log_secrets(self):
        exception = None

        with patch('app.requests.post') as post:
            post.return_value.content = "this would log a secret"
            post.return_value.status_code = 500

            try:
                app.update_envvars({'key': 'secret'}, 'token',
                                   'jpignata/thingie', max_attempts=1,
                                   max_wait=0.001, log=False)
            except Exception as err:
                exception = err

        self.assertNotRegex(str(exception), 'secret')
        self.assertRegex(str(exception), r'this would log a \*{5}')


if __name__ == '__main__':
    unittest.main()

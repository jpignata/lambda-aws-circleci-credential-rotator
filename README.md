# circleci-credential-rotator

## What does it do?

It creates a new IAM Access Key pair, sets it in a CircleCI environment, and
deletes previously existing credentials for a given IAM user.

## Deployment

```bash
sam build
sam deploy
```


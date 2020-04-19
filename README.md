# circleci-credential-rotator

## Summary

This AWS SAM application creates an IAM User that can assume IAM Roles which are
specifically marked with a given tag (i.e. Usage: IntegrationTests) and a Lambda
function to create temporary credentials for that user and set them in to a
CircleCI project's environment variables.

## Deployment

```bash
sam build
sam deploy
```


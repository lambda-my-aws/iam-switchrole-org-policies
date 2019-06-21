#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" iam-switchrole-org-policies """

import re
from os import environ
import logging
import json
import boto3
from troposphere import (
    Template,
)

from troposphere.iam import (
    ManagedPolicy
)

from ozone.handlers.template_manage import create_template_in_s3
from ozone.handlers.stack_manage import create_update_stack

NONALPHANUM = re.compile(r'[^a-zA-Z0-9]')
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def get_account_id():
    """
    Returns self account id
    """
    client = boto3.client('sts')
    return client.get_caller_identity()['Account']


def get_organization_info():
    """
    Returns information about the organization unit the account is into
    """
    client = boto3.client('organizations')
    org = client.describe_organization()
    return org['Organization']


def get_remote_credentials(master_account_id):
    """
    Returns the credentials of assume role
    """
    creds_client = boto3.client('sts')
    creds = creds_client.assume_role(
        RoleArn=f"arn:aws:iam::{master_account_id}:role/{environ['REMOTE_ROLE']}",
        ExternalId=f"{environ['ROLE_EXTERNAL_ID']}",
        RoleSessionName='iam-switchrole-org-policies'
        )['Credentials']
    return creds


def get_ou_accounts(ou_path):
    """
    ou_path: /something or /something/else or / or /root
    """
    master_account_id = get_organization_info()['MasterAccountId']
    creds = get_remote_credentials(master_account_id)
    lambda_client = boto3.client(
        'lambda',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )
    accounts = lambda_client.invoke(
        FunctionName=f"arn:aws:lambda:eu-west-1:{master_account_id}:"
        "function:{environ['RemoteFunctionName']}",
        InvocationType='RequestResponse',
        Payload=json.dumps({'OrganizationUnitName': ou_path})
    )
    accounts_ = json.loads(accounts['Payload'].read().decode('utf-8'))
    return accounts_


def switch_policy(accounts, role_name, ou_path):
    """
    Generates the template policy document for the switch role
    """
    ou_name = ''.join(x.lower().title() for x in ou_path.split('/'))
    ou_name = NONALPHANUM.sub('', ou_name)
    policy_document = {
        'Version': '2012-10-17',
        'Statement': []
    }
    resources = []
    if isinstance(accounts, list):
        for account in accounts:
            resources.append(f'arn:aws:iam::{account["Id"]}:role/{role_name}')
    elif isinstance(accounts, dict):
        resources.append(f'arn:aws:iam::{accounts["Id"]}:role/{role_name}')
    statement = {
        'Sid': f'{role_name.lower()}To{ou_name}',
        'Effect': 'Allow',
        'Action': ['sts:AssumeRole'],
        'Resource': resources,
        "Condition": {
            "BoolIfExists": {
                "aws:MultiFactorAuthPresent": "true"
            },
            "NumericLessThan": {
                "aws:MultiFactorAuthAge": "7200"
            }
        }
    }
    policy_document['Statement'].append(statement)
    return policy_document

def generate_policies(ou_path, accounts, role_name):
    """
    Generates the policies for the accounts in the ou_path
    """
    ou_name = ''.join(x.lower().title() for x in ou_path.split('/'))
    policy_name_prefix = '.'.join(x.lower() for x in ou_path.split('/'))
    if policy_name_prefix.startswith('.'):
        policy_name_prefix = policy_name_prefix[1:]
    policy_name_prefix = '.'.join(x.lower() for x in ou_path.split('/'))
    if policy_name_prefix.startswith('.'):
        policy_name_prefix = policy_name_prefix[1:]
    ou_name = NONALPHANUM.sub('', ou_name)
    policies = []

    if accounts:
        for account in accounts:
            account_name = NONALPHANUM.sub('', account['Name']).lower()
            for role in role_name:
                res_name = f"{role.lower()}to{account_name}"
                policy_res = ManagedPolicy(
                    res_name,
                    ManagedPolicyName=f'{policy_name_prefix}.{account_name}-{role}.access',
                    PolicyDocument=switch_policy(account, role, ou_path),
                    Path=r'/SwitchTo/' + role + f'/{account_name}/',
                    Description=f"Allows AssumeRole for role {role} to "
                    "account {account_name} within OU {ou_name}"
                )
                policies.append(policy_res)
        for role in role_name:
            policy_res = ManagedPolicy(
                f'{role.lower()}to{ou_name.lower()}',
                ManagedPolicyName=f'{policy_name_prefix}-{role}.access',
                PolicyDocument=switch_policy(accounts, role, ou_path),
                Path=r'/switchrole/' + role + r'/',
                Description=f"Allows AssumeRole for role {role} to all accounts in OU {ou_name}"
            )
            policies.append(policy_res)
    return policies


def generate_template(ou_path, accounts, role_name):
    """
    Generates the CFN template for the IAM policies
    """
    tpl = Template()
    tpl.set_description(f'Switch role policies for OU {ou_path}')
    policies = generate_policies(ou_path, accounts, role_name)
    for policy in policies:
        tpl.add_resource(policy)
    bucket_name = environ['TPL_bucket_name']
    template_uri = create_template_in_s3(bucket_name, ou_path, tpl.to_json())
    return template_uri


def lambda_handler(event, context):
    """
    iam-switchrole-org-policies Lambda Handler
    """
    LOGGER.info(event)
    account_id = get_account_id()
    ou_path = event['OrganizationUnitPath']
    role_name = event['RoleName']
    accounts = get_ou_accounts(ou_path)
    if accounts:
        template_uri = generate_template(ou_path, accounts, role_name)
    cfn_client = boto3.client('cloudformation', region_name='us-east-1')
    stack_args = {
        'TemplateURL': template_uri,
        'StackName': f"{ou_path.replace('/', '-')}-assume-role",
        'Capabilities': ['CAPABILITY_NAMED_IAM'],
        'RoleARN': f"arn:aws:iam::{account_id}:role/iam-admin.access"
    }
    stack_id = create_update_stack(cfn_client, **stack_args)
    return stack_id

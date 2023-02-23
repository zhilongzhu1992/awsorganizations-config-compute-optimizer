#!/usr/bin/env python3

# The purpose of this script is to create a Config Aggregator
# in an Organizations Member Account that Aggregates all of your
# Organization's Member Accounts across all supported Regions.
# Note: you must run this in an Organizations Master Account

# Each Member Account must have an OrganizationAccountAccessRole
# that matches the string provided to the variable ORGS_ACCESS_ROLE_NAME
# the OrganizationAccountAccessRole must have the proper IAM permissions

import boto3
import os
import botocore

ORGS_ACCESS_ROLE_NAME = 'OrganizationAccountAccessRole'



config_regions=boto3.session.Session().get_available_regions('config')
#session = boto3.Session(profile_name='ug-mem')
aggregation_accounts_with_errors = []

continue_on_error = None
def keep_going(account):
        print('An error occoured in ' + account)
        global continue_on_error
        while continue_on_error not in ['y', 'a']:
            continue_on_error = input('Do you want to continue? Y/A/N: ')
            if continue_on_error.lower().startswith('y'):
                print("Continuing")
                continue_on_error = 'unknown'
                return
            elif continue_on_error.lower().startswith('a'):
                print("Continuing")
                continue_on_error = 'a'
            elif continue_on_error.lower().startswith('n'):
                print("Exiting")
                exit(1)
def my_clear():
 
    # for windows
    if os.name == 'nt':
        _ = os.system('cls')
 
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = os.system('clear')

def list_all_accounts_orgs(profile_name=None, No_Output=False):
    if profile_name is None:
        orgs = boto3.client('organizations')
    else:
        session = boto3.Session(profile_name=profile_name)
        orgs = session.client('organizations')
    orgs = boto3.client('organizations')
    
    try:
        organization = orgs.describe_organization()['Organization']
    except Exception as e:
        print(e)
        exit(1)

    master_account_id = organization['MasterAccountId']
    try:
        account_ids = []
        paginator = orgs.get_paginator('list_accounts')
        account_nums=0
        for page in paginator.paginate():
            for account in page['Accounts']:
                account_ids.append(account['Id'])
                if account['Id'] == master_account_id:
                    acc_type="Master"
                else:
                    acc_type="Member"
                if not No_Output:
                    print("[{}]   Account Id:{} Account Type:{}".format(account_nums, account['Id'], acc_type))
                    account_nums += 1
    except Exception as e:
        print(e)
    return [account_ids, master_account_id]

def list_acc_with_config(Type=0, RecorderName=""):
    result=list_all_accounts_orgs(No_Output=True)
    account_ids=result[0]
    master_account_id=result[1]
    config_recorders_status={}
    master=False
    for acc in account_ids:
        if acc == master_account_id:
            master=True
        else:
            sts = boto3.client('sts')
            mem_orgs_role_arn = 'arn:aws:iam::' + \
            acc + ':role/' + ORGS_ACCESS_ROLE_NAME
            #print(mem_orgs_role_arn)
            try:
                credentials = sts.assume_role(
                    RoleArn=mem_orgs_role_arn,
                    RoleSessionName='Config-Recorder-Test',
                    )['Credentials']
            except Exception as e:
                print(e)
                exit(1)
            acc_session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                                             aws_secret_access_key=credentials['SecretAccessKey'],
                                             aws_session_token=credentials['SessionToken'],
                    )
        for region in  config_regions:
            try:
                #print("account id :{} region: {}".format(acc, region))
                if master:
                    config_client=boto3.client("config", region_name=region)
                else:
                    config_client = acc_session.client('config',
                                region_name=region
                              )
                if Type == 0:
                    config_recorder_status=config_client.describe_configuration_recorder_status()
                    if len(config_recorder_status['ConfigurationRecordersStatus']):
                        config_recorder_status=config_recorder_status['ConfigurationRecordersStatus'][0]
                        if acc not in config_recorders_status.keys():
                            config_recorders_status[acc]={}
                        else:
                            config_recorders_status[acc][region]=config_recorder_status
                        if config_recorder_status["recording"] == True:
                            print("Account Id: {} Region : {} Config: {}".format(acc, region, "Enabled"))
                        else:
                            print("Account Id: {} Region : {} Config: {}".format(acc, region, "Disabled"))
            except Exception as e:
                #print(e)
                #print("config service doesn't support {} region!!".format(region))
                continue
    return config_recorders_status
"""   
def put_auth(config_client, aggregator_account, aggregator_region, config_region, authorization_account):
    try:
        config_client.put_aggregation_authorization(
            AuthorizedAccountId=aggregator_account,
            AuthorizedAwsRegion=aggregator_region
        )
        authorizations = config_client.describe_aggregation_authorizations()
        print('Sucessfully authorized Aggregator in ' + config_region + ' in ' + authorization_account + ': ')
        for authorization in authorizations.get('AggregationAuthorizations'):
            if authorization.get('AuthorizedAwsRegion') == config_region:
                print(authorization.get('AuthorizedAwsRegion'))
                print('Success!')
    except Exception as re:
        print('Error accpeting in ' + config_region)
        print(re)
        return(re)

def delete_auth(config_client, aggregator_account, aggregator_region, config_region, authorization_account):
    try:
        config_client.delete_aggregation_authorization(
            AuthorizedAccountId=aggregator_account,
            AuthorizedAwsRegion=aggregator_region
        )
        authorizations = config_client.describe_aggregation_authorizations()
        print('Sucessfully Deleted authorization in Region ' + config_region + ' in ' + authorization_account + ': ')
        for authorization in authorizations.get('AggregationAuthorizations'):
            print('Deleting authorizations in ' + account + ' ' + config_region)
    except Exception as re:
        print('Error deleting in ' + config_region)
        print(re)
        pass
"""
def display_menu(options):
    print("Start".center(50, "*"))
    for key, value in supported_funcs.items():
        tmp_str="[{}] {}".format(key, value[0])    
        print(tmp_str.ljust(50, " "))
    print("End".center(50, "*"))
    while True:
        option=input("Please Choose which action you want to perform:(1, 2, etc):")
        if option not in options:
            print("You have to choose the above mentioned options, please try again!")
        return option

def disable_config_in_acc():
    config_recorders_status=list_acc_with_config()
    if len(config_recorders_status) == 0:
        print("No Config Recorders in any account of Orgs")
    for key, value in config_recorders_status.items():
        for k, v in value.items():
            if v["recording"]:
                pass    
def list_compute_optimizer_status_for_orgs(No_Output=False):
    account_ids=[]
    try:
        com_opt_client=boto3.client('compute-optimizer')
        response=com_opt_client.get_enrollment_statuses_for_organization()
        account_statuses=response["accountEnrollmentStatuses"]
        if len(account_statuses):
            for i in account_statuses:
                if not No_Output:
                    print("accountId:[{}] Status:[{}] LastUpdateTime:[{}]".format(i["accountId"], i["status"], i["lastUpdatedTimestamp"]))
                account_id_status=[]
                account_id_status.append(i["accountId"])
                account_id_status.append(i["status"])
                account_ids.append(account_id_status)
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'OptInRequiredException':
            print("The current account is not opted in yet!")
            print("Please opt in first!")
    except Exception as e:
        print(e)
    return account_ids


def disable_or_enable_compute_optimizer_for_orgs(Mode):
    #account_ids=list_compute_optimizer_status_for_orgs(No_Output=True)
    if option:
        result=list_all_accounts_orgs(No_Output=True)
        account_ids=result[0]
        master_account_id=result[1]
        for acc in account_ids:
            if acc == master_account_id:
                com_opt_client=boto3.client('compute-optimizer')
            else:
                sts = boto3.client('sts')
                mem_orgs_role_arn = 'arn:aws:iam::' + \
                acc + ':role/' + ORGS_ACCESS_ROLE_NAME
                #print(mem_orgs_role_arn)
                try:
                    credentials = sts.assume_role(
                        RoleArn=mem_orgs_role_arn,
                        RoleSessionName='Config-Recorder-Test',
                        )['Credentials']
                except Exception as e:
                    print(e)
                    continue
                acc_session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                                             aws_secret_access_key=credentials['SecretAccessKey'],
                                             aws_session_token=credentials['SessionToken'],
                    )
                com_opt_client=acc_session.client('compute-optimizer')
            try:
                response=com_opt_client.update_enrollment_status(status=Mode, includeMemberAccounts=False)
                #print("AccountId: [{}] Status: []".format(acc, response['status']))
            except Exception as e:
                print(e)
    
def enable_compute_optimizer_for_orgs():
    try:
        org_client=boto3.client('organizations')
        response=org_client.list_aws_service_access_for_organization()
        services=response["EnabledServicePrincipals"]
        is_compute_optimizer_trusted_for_org=False
        if len(services):
            for i in services:
                if i["ServicePrincipal"] == "compute-optimizer.amazonaws.com":
                    is_compute_optimizer_trusted_for_org=True
           
        if not is_compute_optimizer_trusted_for_org:
            org_client.enable_aws_service_access(ServicePrincipal="compute-optimizer.amazonaws.com")
    except Exception as e:
        print(e)
    disable_or_enable_compute_optimizer_for_orgs("Active")
    list_compute_optimizer_status_for_orgs()

def disable_compute_optimizer_for_orgs():
    disable_or_enable_compute_optimizer_for_orgs("Inactive")
    list_compute_optimizer_status_for_orgs()

def my_exit():
    exit()

def go_back_to_main_menu():
    while True:
        choice=input("Go back to Main Menu? Yes or No:")         

supported_funcs={"1":["List All Accounts in Orgs ", list_all_accounts_orgs], \
                 "2":["List ALL Accounts with config recorder configured in Orgs", list_acc_with_config], \
                 "3":["Disable Config in an Account with Config Enabled in Orgs", disable_config_in_acc], \
                 "4":["List Compute Optimizer Statuses for Orgs", list_compute_optimizer_status_for_orgs], \
                 "5":["Disable Compute Optimizer for Orgs", disable_compute_optimizer_for_orgs], \
                 "6":["Enable Compute Optimizer for Orgs", enable_compute_optimizer_for_orgs], \
                 "7":["Exit the Program", my_exit]}

if __name__ ==  "__main__":
    my_clear()
    while True:
        options=supported_funcs.keys()
        option=display_menu(options)
        supported_funcs[option][-1]()

#!/usr/bin/env python3
import sys
import logging
from collections import defaultdict
from app.logger import logger
from app.xiq_api import XIQ, APICallFailedException
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
logger = logging.getLogger('XIQ-AD-PPSK_Sync.Main')



####################################
# written by:   Tim Smith
# e-mail:       tismith@extremenetworks.com
# date:         28 Aug 2025
# version:      3.0.0
####################################


# Global Variables - ADD CORRECT VALUES
server_name = "enter the server name/ IP"
domain_name = "enter the domain name"
user_name = "enter AD username"
password = " enter AD password"

#AD MaxPageSize 
page = 1000
#AD Filter to search
AD_Filter = ""

#XIQ MaxPageSize (max is 100)
pageSize = 100

#XIQ_username = "enter your ExtremeCloudIQ Username"
#XIQ_password = "enter your ExtremeCLoudIQ password"
####OR###
## TOKEN permission needs - enduser, pcg:key
XIQ_token = "****"

group_roles = [
    # AD GROUP Distinguished Name, XIQ group ID
    ("AD Group Distinguished Name", "XIQ User Group ID"),
    ("AD Group Distinguished Name", "XIQ User Group ID")
]

PCG_Enable = False

PCG_Mapping = {
    "XIQ User Group ID" : {
        "UserGroupName": "XIQ User Group Name",
        "policy_id": "Network Policy ID associated with PCG",
         "policy_name": "Network Policy name associated with PCG"
    }
}

# userAccountControl codes used for disabled accounts
ldap_disable_codes = ['514','642','66050','66178']

def retrieveADUsers(ad_group):
    #Building search base from fqdn
    subdir_list = domain_name.split('.')
    tdl = subdir_list[-1]
    subdir_list = subdir_list[:-1]
    if subdir_list:
        SearchBase = 'DC=' + ',DC='.join(subdir_list) + ',DC=' + tdl
    else:
        SearchBase = 'DC=' + tdl
    ad_result = []
    try:
        server = Server(server_name, get_info=ALL)
        conn = Connection(server, user='{}\\{}'.format(domain_name, user_name), password=password, authentication=NTLM, auto_bind=True)
        conn.search(
            search_base= SearchBase,
            search_filter='(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={}){})'.format(ad_group,AD_Filter),
            search_scope=SUBTREE,
            attributes = ['objectClass', 'userAccountControl', 'sAMAccountName', 'name', 'mail'],
            paged_size = page)
        ad_result.extend(conn.entries)
        print(f"completed page of AD Users. Total Users collected is {len(ad_result)}")
        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        while cookie:
            conn.search(
                search_base= SearchBase,
                search_filter='(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={}){})'.format(ad_group,AD_Filter),
                search_scope=SUBTREE,
                attributes = ['objectClass', 'userAccountControl', 'sAMAccountName', 'name', 'mail'],
                paged_size = page,
                paged_cookie = cookie)
            ad_result.extend(conn.entries)
            print(f"completed page of AD Users. Total Users collected is {len(ad_result)}")
            cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        conn.unbind()
        return ad_result
    except:
        logger.error(f"Unable to reach server {server_name}")
        print("script exiting....")
        raise SystemExit

def get_ppsk_user_id_by_email(ppsk_users, email):
    for user in ppsk_users:
        if user.get('email_address') == email:
            return user.get('id')
    logger.info(f"No PPSK user found with email {email}", extra={'file_only': True})
    return None

def get_ppsk_user_group_by_id(ppsk_users, user_id):
    for user in ppsk_users:
        if user.get('id') == user_id:
            return user.get('user_group_id')
    logger.info(f"No PPSK user found with ID {user_id}", extra={'file_only': True})
    return None

def get_pcg_user_id_by_email(pcg_users, email):
    for user in pcg_users:
        if user.get('email') == email:
            return user.get('id')
    logger.info(f"No PCG user found with email {email}", extra={'file_only': True})
    return None
   
def main():
    if 'XIQ_token' not in globals():
        try:
            x = XIQ(username=XIQ_username,password=XIQ_password)
        except:
            print(f"API to create XIQ session failed with {e}")
            print("exiting script...")
            raise SystemExit
    else:
        x = XIQ(token=XIQ_token)
    
    ListOfADgroups, ListOfXIQUserGroups = zip(*group_roles)

    # Collect PSK users
    ppsk_users = []
    for usergroupID in ListOfXIQUserGroups:
        try:
            ppsk_users += x.retrievePPSKUsers(usergroupID)
        except APICallFailedException as err:
            logger.error(f"API to retrieve PPSK users failed with {err}")
            print("script exiting....")
            raise SystemExit
    logger.info("Successfully parsed " + str(len(ppsk_users)) + " XIQ users")

    # Collect PCG Users if enabled
    if PCG_Enable == True:
        pcg_capture_success = True
        pcg_users = []
        for pcg_policy in PCG_Mapping.values():
            try:
                pcg_users += x.retrievePCGUsers(pcg_policy['policy_id'])
            except APICallFailedException as err:
                pcg_capture_success = False
                logger.error(f"API to retrieve PCG users failed with {err}")
                continue
            logger.info(f"Successfully parsed {len(pcg_users)} PCG users from policy {pcg_policy['policy_name']}")

    # Collect LDAP Users
    ldap_users = {}
    ldap_capture_success = True
    for ad_group, xiq_user_role in group_roles:
        ad_result = retrieveADUsers(ad_group)
        for ldap_entry in ad_result:
            if str(ldap_entry.name) not in ldap_users:
                try:
                    ldap_users[str(ldap_entry.name)] = {
                        "userAccountControl": str(ldap_entry.userAccountControl),
                        "email": str(ldap_entry.mail),
                        "username": str(ldap_entry.sAMAccountName),
                        "xiq_role": xiq_user_role
                    }
                except Exception as err:
                    logger.error(f"Failed to collect LDAP users with error {str(err)}")
                    logger.error(f"{sys.exc_info()[0]}")
                    logger.warning("User info was not captured from Active Directory")
                    logger.warning(f"{ldap_entry}")
                    # not having ppsk will break later line - for name, details in ldap_users.items():
                    ldap_capture_success = False
                    continue
            else:
                logger.error(f"User {ldap_entry.name} has multiple entries. This entry will not be added to PPSK")
                logger.warning(f"{ldap_entry}")

    logger.info("Successfully parsed " + str(len(ldap_users)) + " LDAP users")

    batch_size = 100 # batch count for PCG users if enabled

    # Precompute sets for O(1) lookups
    current_ppsk_user_names = {d.get('user_name') for d in ppsk_users if isinstance(d, dict) and 'user_name' in d }
    current_pcg_user_names = {d.get('name') for d in pcg_users if isinstance(d, dict) and 'name' in d } if PCG_Enable else set()
    disable_codes = set(ldap_disable_codes)
    # Track Error counts
    ppsk_create_error = 0
    pcg_create_error = 0
    ppsk_del_error = 0
    pcg_del_error = 0

    # Make a list of PPSK users to create
    ldap_disabled = []
    new_ppsk_users = []
    pcg_batch = defaultdict(list) if PCG_Enable else None  # List to collect successful PPSK users for PCG

    # Step 1: Identify new users for PPSK
    for name, details in ldap_users.items():
        # Safely access email and userAccountControl
        email = details.get('email')
        user_account_control = details.get('userAccountControl')

        # Skip if email is missing
        if not email or email == '[]':
            logger.warning(f"User {name} doesn't have an email set and will not be created in xiq")
            continue
        # Check if user is new and not disabled
        if name not in current_ppsk_user_names and user_account_control not in disable_codes:
            xiq_role = details.get('xiq_role')
            if PCG_Enable == True and str(xiq_role) in PCG_Mapping:
                if name not in current_pcg_user_names:
                    pcg_batch[xiq_role].append((name, email))
                else:
                    logger.info(f"User {name} already exists in PCG, skipping PCG creation")
            else:
                new_ppsk_users.append((name, email, xiq_role))
        elif any(d == details['userAccountControl'] for d in ldap_disable_codes):
            ldap_disabled.append(name)
        total_users = sum(len(PCGUsers) for PCGUsers in pcg_batch.values()) if pcg_batch else 0
        # If batch size reached, process the batch
        if total_users >= batch_size:
            for xiq_role, PCGUsers in pcg_batch.items():
                if not PCGUsers:
                    continue
                policy_id = PCG_Mapping[str(xiq_role)]['policy_id']
                policy_name = PCG_Mapping[str(xiq_role)]['policy_name']
                user_group_name = PCG_Mapping[str(xiq_role)]['UserGroupName']
                try:
                    logger.info(f"Adding {len(PCGUsers)} users to PCG policy {policy_name}")
                    pcg_response = x.addPCGUsers(policy_id, PCGUsers, user_group_name)
                except APICallFailedException as err: 
                    logger.error(f"API to add PCG users to policy {policy_name} failed with {err}")
                    logger.error(f"List of PCG users failed to add: {str(PCGUsers)}", extra={'file_only': True})
                    pcg_create_error += len(PCGUsers)
                    continue 
                except Exception as err:
                    logger.error(f"API to add PCG users to policy {policy_name} failed with {str(err)}")
                    logger.error(f"List of PCG users failed to add: {str(PCGUsers)}", extra={'file_only': True})
                    pcg_create_error += len(PCGUsers)
                    continue
                logger.info(f"Successfully added {len(PCGUsers)} users to PCG policy {policy_name}")
                logger.info(f"List of PCG users added: {str(PCGUsers)}", extra={'file_only': True})
            pcg_batch = defaultdict(list)  # Reset batch

    # Process any remaining users in the batch
    total_users = sum(len(PCGUsers) for PCGUsers in pcg_batch.values()) if pcg_batch else 0
    if PCG_Enable and total_users > 0:
        # Process any remaining users in the batch
        for xiq_role, PCGUsers in pcg_batch.items():
            if not PCGUsers:
                continue
            policy_id = PCG_Mapping[str(xiq_role)]['policy_id']
            policy_name = PCG_Mapping[str(xiq_role)]['policy_name']
            user_group_name = PCG_Mapping[str(xiq_role)]['UserGroupName']
            try:
                logger.info(f"Adding {len(PCGUsers)} users to PCG policy {policy_name}")
                pcg_response = x.addPCGUsers(policy_id, PCGUsers, user_group_name)
            except APICallFailedException as err: 
                logger.error(f"API to add PCG users to policy {policy_name} failed with {err}")
                logger.error(f"List of PCG users failed to add: {str(PCGUsers)}", extra={'file_only': True})
                pcg_create_error += len(PCGUsers)
                continue 
            except Exception as err:
                logger.error(f"API to add PCG users to policy {policy_name} failed with {str(err)}")
                logger.error(f"List of PCG users failed to add: {str(PCGUsers)}", extra={'file_only': True})
                pcg_create_error += len(PCGUsers)
                continue
            logger.info(f"Successfully added {len(PCGUsers)} users to PCG policy {policy_name}")
            logger.info(f"List of PCG users added: {str(PCGUsers)}", extra={'file_only': True})
        pcg_batch = defaultdict(list)
    
    # Process new PPSK users
    if new_ppsk_users:
        # Step 2: Create PPSK users
        for name, email, xiq_role in new_ppsk_users:
            try:
                user_created = x.createPPSKUser(name, email, xiq_role)
            except APICallFailedException as err:
                logger.error(f"API to create PPSK user {name} failed with {err}")
                ppsk_create_error += 1
                continue
            except Exception as err:
                logger.error(f"API to create PPSK user {name} failed with {str(err)}")
                ppsk_create_error += 1
                continue

    # Make a list of users to delete
    if ldap_capture_success:
        # Remove disabled accounts from ldap users
        for name in ldap_disabled:
            logger.info(f"User {name} is is disabled in AD with disable code {ldap_users[name]['userAccountControl']}.")
            del ldap_users[name]

        pcg_users_to_delete = defaultdict(list) if PCG_Enable else None
        ppsk_users_to_delete = []

        for ppsk_user in ppsk_users:
            user_group_id = ppsk_user['user_group_id']
            email = ppsk_user['email_address']
            ppsk_user_id = ppsk_user['id']
            # check if any xiq user is not included in active ldap users
            if not any(d['email'] == email for d in ldap_users.values()):
                if PCG_Enable == True and str(user_group_id) in PCG_Mapping:
                    if pcg_capture_success == False:
                        logger.error(f"Due to PCG read failure, user {email} cannot be deleted")
                        ppsk_del_error+=1
                        pcg_del_error+=1
                        continue
                    # If PCG is Enabled, Users need to be deleted from PCG group before they can be deleted from User Group
                    pcg_user_id = get_pcg_user_id_by_email(pcg_users, email)
                    if pcg_user_id is not None:
                        pcg_users_to_delete[user_group_id].append((ppsk_user_id, email)) 
                        # If batch size reached, process the batch
                        if sum(len(PCGUserIds) for PCGUserIds in pcg_users_to_delete.values()) >= batch_size:
                            for xiq_role, pcg_users_ids in pcg_users_to_delete.items():
                                if not pcg_users_ids:
                                    continue
                                policy_id = PCG_Mapping[str(xiq_role)]['policy_id']
                                policy_name = PCG_Mapping[str(xiq_role)]['policy_name']
                                max_pcg_user_count = 500 # Max PCG users allowed to delete in one call
                                for i in range(0, len(pcg_users_ids), max_pcg_user_count):
                                    pcg_user_batch = pcg_users_ids[i:i + max_pcg_user_count]
                                    print(f"Deleting {len(pcg_user_batch)} users from PCG policy {policy_name}")
                                    try:
                                        result = x.deletePCGUsers(policy_id, pcg_user_batch)
                                    except APICallFailedException as err:
                                        logger.error(f"API to delete {len(pcg_user_batch)} PCG users from policy {policy_name} failed with {err}")
                                        logger.error(f"List of PCG users ids failed: {str(pcg_user_batch)}", extra={'file_only': True})
                                        pcg_del_error += 1
                                        continue
                                    except Exception as err:
                                        logger.error(f"API to delete {len(pcg_user_batch)} PCG users from policy {policy_name} failed with {str(err)}")
                                        logger.error(f"List of PCG users ids failed: {str(pcg_user_batch)}", extra={'file_only': True})
                                        pcg_del_error += 1
                                        continue
                                    if result:
                                        logger.info(f"Successfully deleted {len(pcg_user_batch)} PCG users from policy {policy_name}")
                                        logger.info(f"List of PCG users ids deleted: {str(pcg_user_batch)}", extra={'file_only': True})
                            pcg_users_to_delete = defaultdict(list)  # Reset batch
                    else:
                        logger.warning(f"User {email} not found in PCG, skipping PCG deletion")
                        pcg_del_error += 1
                # Add to PPSK users to delete
                ppsk_users_to_delete.append((ppsk_user_id, email))

        # Process any remaining users in the batch
        if PCG_Enable == True and pcg_capture_success == True:
            if sum(len(PCGUserIds) for PCGUserIds in pcg_users_to_delete.values()) > 0:
                for xiq_role, pcg_users_ids in pcg_users_to_delete.items():
                    if not pcg_users_ids:
                        continue
                    policy_id = PCG_Mapping[str(xiq_role)]['policy_id']
                    policy_name = PCG_Mapping[str(xiq_role)]['policy_name']
                    print(f"Deleting {len(pcg_users_ids)} users from PCG policy {policy_name}")
                    try:
                        result = x.deletePCGUsers(policy_id, pcg_users_ids)
                    except APICallFailedException as err:
                        logger.error(f"API to delete {len(pcg_users_ids)} PCG users from policy {policy_name} failed with {err}")
                        logger.error(f"List of PCG users ids failed: {str(pcg_users_ids)}", extra={'file_only': True})
                        pcg_del_error += len(pcg_users_ids)
                        continue
                    except Exception as err:
                        logger.error(f"API to delete {len(pcg_users_ids)} PCG users from policy {policy_name} failed with {str(err)}")
                        logger.error(f"List of PCG users ids failed: {str(pcg_users_ids)}", extra={'file_only': True})
                        pcg_del_error += len(pcg_users_ids)
                        continue
                    if result:
                        logger.info(f"Successfully deleted {len(pcg_users_ids)} PCG users from policy {policy_name}")
                        logger.info(f"List of PCG users ids deleted: {str(pcg_users_ids)}", extra={'file_only': True})
                pcg_users_to_delete = defaultdict(list)  # Reset batch
        # Step 3: Delete PPSK users
        for ppsk_user_id, email in ppsk_users_to_delete:
            try:
                result = x.deletePPSKUser(ppsk_user_id)
            except APICallFailedException as err:
                logger.error(f"API to delete PPSK user ID {ppsk_user_id} failed with {err}")
                ppsk_del_error += 1
                continue
            except Exception as err:
                logger.error(f"API to delete PPSK user ID {ppsk_user_id} failed with {str(err)}")
                ppsk_del_error += 1
                continue
            if result:
                    logger.info(f"User {email} - {ppsk_user_id} was successfully deleted.")

        if ppsk_create_error:
            logger.info(f"There were {ppsk_create_error} errors creating PPSK users on this run.")
        if pcg_create_error:
            logger.info(f"There were {pcg_create_error} errors creating PCG users on this run.")
        if ppsk_del_error:
            logger.info(f"There were {ppsk_del_error} errors deleting PPSK users on this run.")
        if pcg_del_error:
            logger.info(f"There were {pcg_del_error} errors deleting PCG users on this run.")

    else:
        logger.warning("No users will be deleted from XIQ because of the error(s) in reading ldap users")

if __name__ == '__main__':
	main()
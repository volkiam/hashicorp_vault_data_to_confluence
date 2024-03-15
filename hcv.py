import requests, json, base64
from atlassian import Confluence
from bs4 import BeautifulSoup


# Start: Read config file
with open('config.json', 'r') as f:
    config = json.load(f)

server_url  = config["server_url"]
server_port = config["server_port"]
username    = config["username"]
password    = base64.b64decode(config["password"]).decode().strip()
token    = base64.b64decode(config["token"]).decode().strip()

confluence_space                 = config["confluence_space"]
confluence_page_mapping_policies = config["confluence_page_mapping_policies"]
confluence_page_policies         = config["confluence_page_policies"]
confluence_url                   = config["confluence_url"]
# End: Read config file

# Connect to confluence
def confluence_session_setup(confluence_url: str, username: str, password: str, token: str) -> Confluence:
    """
    Configures the connection to Confluence and checks the access mode.

    Two authentication methods avaiable: username and password ot token. Please, set value for one of them.
    Args:
        confluence_url (str): The URL of the Confluence instance.
        username (str): The authentication username for accessing Confluence. 
        password (str): The authentication password for accessing Confluence.
        token (str): The authentication token for accessing Confluence.

    Returns:
        Confluence: An instance of the Confluence client if the access mode is not anonymous.
    """
    # configures confluence connection and checks access mode

    if token:
        confluence_client = Confluence(
            url = confluence_url,
            token = token
        )
    else:
         confluence_client = Confluence(
            url = confluence_url,
            username = username, 
            password = password
        )       
    return confluence_client

# Update confluence page - update table
def update_confluence_page(confluence_client: Confluence, confluence_space: str, confluence_page: str, headers: str, table_body: str) -> None:
    """
    Gets a Confluence page and update it.
    Args:
        confluence_client (ConfluenceClient): The Confluence client object.
        confluence_page (str): The ID of the Confluence page.
        headers (dict): Table headers.
        table_body (str): Table body.
    Returns:
        None
    """

    confluence_page_id = confluence_client.get_page_id ( confluence_space, confluence_page )
    if confluence_page_id is not None:    
        confluence_page = {}
        response = confluence_client.get_page_by_id (
            page_id = confluence_page_id,
            expand = 'body.storage'
        )

        html = BeautifulSoup(
            markup = response['body']['storage']['value'],
            features = 'html.parser'
        )

        confluence_page.update({'title': response['title'], 'html': html})

        tables = confluence_page['html'].find_all('table') # table[0] - service owners table, table[1] - data table
        table = tables[1]
        
        if table:
            # Create new table
            table_new = "<table>\n"
            table_new += "<tr>\n"
            table_new += headers
            table_new += "</tr>\n"
            table_new += table_body
            table_new += "</table>"

            # Replace the old table HTML with the new one
            table.replace_with(BeautifulSoup(table_new, 'html.parser'))
            new_body = html.prettify()

            confluence_client.update_page(
                page_id = confluence_page_id,
                body = new_body,
                title = confluence_page['title']
            )

# Get session token
def get_session_token (username: str, password: str):
    """
        Get session token for Hashicorp Vault instance. 
        Only for LDAP auth data
        Args:
            username (str): Name of the user
            password (str): Password of the user
        Returns:
            client token (str)
    """
    headers = {
        'Content-Type': 'application/json'
        }
    payload = {
               'password': password
               }
    url = f'{server_url}:{server_port}/v1/auth/ldap/login/{username}'
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code in [200,201]:
        client_token = response.json().get("auth").get("client_token")
    else:
        client_token = ""
        print(f'Error within get session token. Error: {response.status_code}')
    return client_token

# Get ldap users list
def get_ldap_users_list (client_token: str):
    """
        Get list of ldap users in Hashicorp Vault
        Args:
            client_token (str): Access token to Hashicorp Vault
        Returns:
            LDAP users (dict)
    """
    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Token': client_token
        }
    url = f'{server_url}:{server_port}/v1/auth/ldap/users'
    response = requests.get(url = url, headers=headers, params={"list":"true"})
    if response.status_code in [200,201]:
        ldap_users_list = response.json().get("data").get("keys")
    else:
        ldap_users_list = ""
        print(f'Error within retrive ldap users list. Error: {response.status_code}')
    return ldap_users_list

# Get ldap user info
def get_ldap_user_info (username: str, client_token: str):
    """
        Get ldap group information from Hashicorp Vault 
        Args:
            username (str): Name of ldap user
            client_token (str): Access token to Hashicorp Vault
        Returns:
            user info (json (groups:dict, policies:dict) )
    """
    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Token': client_token
        }
    url = f'{server_url}:{server_port}/v1/auth/ldap/users/{username}'
    response = requests.get(url, headers=headers)
    if response.status_code in [200,201]:
        user_info = response.json().get("data")
    else:
        user_info = ""
        print(f'Error within retrive ldap user info. Error: {response.status_code}')
    return user_info

# Get ldap group list
def get_ldap_groups_list (client_token: str):
    """
        Get list of ldap groups in Hashicorp Vault
        Args:
            client_token (str): Access token to Hashicorp Vault
        Returns:
            LDAP groups (dict)  
    """
    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Token': client_token
        }
    url = f'{server_url}:{server_port}/v1/auth/ldap/groups'
    response = requests.get(url = url, headers=headers, params={"list":"true"})
    if response.status_code in [200,201]:
        ldap_groups_list = response.json().get("data").get("keys")
    else:
        ldap_groups_list = ""
        print(f'Error within retrive ldap groups list. Error: {response.status_code}')
    return ldap_groups_list

# Get ldap group info
def get_ldap_group_info (groupname: str, client_token: str):
    """
        Get ldap group information from Hashicorp Vault 
        Args:
            groupname (str): Name of ldap group
            client_token (str): Access token to Hashicorp Vault
        Returns:
            group info (json (policies:dict) )
    """
    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Token': client_token
        }
    url = f'{server_url}:{server_port}/v1/auth/ldap/groups/{groupname}'
    response = requests.get(url, headers=headers)
    if response.status_code in [200,201]:
        group_info = response.json().get("data")
    else:
        group_info = ""
        print(f'Error within retrive ldap group info. Error: {response.status_code}')
    return group_info

# Get policies
def get_list_of_policies(client_token: str):
    """
        Get list of vault policy
        Args:
            client_token (str): Access token to Hashicorp Vault
        Returns:
            list of policies (dict)
    """

    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Token': client_token
        }
    url = f'{server_url}:{server_port}/v1/sys/policy'
    response = requests.get(url, headers=headers)
    if response.status_code in [200,201]:
        policies = response.json().get("data").get("policies")
    else:
        policies = ""
        print(f'Error within get policies. Error: {response.status_code}')
    return policies

# Get policy info
def get_policy_info (policy_name: str, client_token: str):
    headers = {
        'Content-Type': 'application/json',
        'X-Vault-Token': client_token
        }
    """
        Get information for vault policy by name
        Args:
            policy_name (str): Name of policy
            client_token (str): Access token to Hashicorp Vault
        Returns:
            policy info (str)
    """
    url = f'{server_url}:{server_port}/v1/sys/policy/{policy_name}'
    response = requests.get(url, headers=headers)
    if response.status_code in [200,201]:
        policy_info = response.json().get("data").get("rules")
    else:
        policy_info = ""
        print(f'Error within get policy info. Error: {response.status_code}')
    return policy_info

# Create new row 
def create_row (values: dict): 
        """
        Create new row for html table
        Args:
            values (dict): Columns data  
        Returns:
            row (str)
        """
        row = "<tr>\n"
        for value in values:
            row += f"<td>{value}</td>"
        row += "\n</tr>\n"
        return row

# Update mapping pocies page
def update_mapping_policies_page (client_token: str, confluence_client: Confluence) -> None:
    """
        Update confluence page (mapping policies)
        Args:
           client_token: Access token to Hashicorp Vault
           confluence_client: Confluence client
        Returns:
            None
    """

    table_body = ''
    table_headers = ''

    headers = ["Имя учетной записи", "Тип", "Политики", "Группы"]
    for header in headers:
        table_headers += "<th>{0}</th>\n".format(header.strip())

    users = get_ldap_users_list (client_token)
    for user in users:
        user_info = get_ldap_user_info (user,client_token)
        table_body += create_row ([user,'Пользователь LDAP','<br/>'.join(user_info.get("policies")),user_info.get("groups")])

    groups = get_ldap_groups_list (client_token)
    for group in groups:
        group_info = get_ldap_group_info (group,client_token)
        group_list = ""
        if group_info.get("groups") is not None: 
            group_list = '<br/>'.join(group_info.get("groups"))
        table_body += create_row ([group,'Группа LDAP','<br/>'.join(group_info.get("policies")), group_list])

    update_confluence_page(confluence_client, confluence_space, confluence_page_mapping_policies, table_headers, table_body)

def update_policies_page (client_token: str, confluence_client: Confluence) -> None:
    """
        Update confluence page (policies)
        Args:
           client_token: Access token to Hashicorp Vault
           confluence_client: Confluence client
        Returns:
            None
    """

    table_body = ''
    table_headers = ''

    headers = ["Политика", "Правила"]
    for header in headers:
        table_headers += "<th>{0}</th>\n".format(header.strip())

    policies = get_list_of_policies (client_token)
    for policy in policies:
        policy_rules = get_policy_info (policy, client_token)
        policy_rules = policy_rules.replace("\n","<br/>")
        table_body += create_row ([policy, policy_rules])


    update_confluence_page(confluence_client, confluence_space, confluence_page_policies, table_headers, table_body)


def main() -> None:
    """main"""
    
    confluence_client = confluence_session_setup(confluence_url, username, password, token )
    client_token      = get_session_token (username, password)
    
    update_mapping_policies_page (client_token, confluence_client)
    update_policies_page (client_token, confluence_client)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print('Error: '+ str(e))
        raise
# KeyVault

Basic KeyVault API for storing secrets.

## Authentication

All operations require authentication with a JWT token.

Retrieve a JWT token with
- Windows authentication [endpoint /auth/windows]
- Username/password authentication [endpoint /auth/basic]

## Users

Users can be added by POSTing to /user  
Authentcation for a users can be added by PUTing to
- Windows authentication /user/credential/{userId}/windows
- Basic authentication /user/credential/{userId}/basic

## Roles

Roles give users authorization for everything but secrets
- Admin [can execute all operations]
- UserManagement [can add/update/delete users, add credentials and roles to users]
- CreateSecret [can create new secret descriptors]
- ListSecrets [allows a user to list their own secrets]

## Secrets

### New secret
Create a new secret by POSTing to /secret/descriptor  
The user creating the secret descriptor, gets read/write/assign permissions for the secret

### Secret values
A secret descriptor is only a container for secret values  
Add secret values by POSTing to /secret/data  

### Granting access to a secret descriptor
With the assign permission, a user can grant access to a secret descriptor  
By POSTing to /secret/access/{secretName}, access (read, write and/or assign) can be granted to other users

### Update a secret value
Send a PUT request to /secret/data/{secretName} (requires write permission)

### Delete a secret descriptor
Deletes the secret descriptor and all secret values  
Send a DELETE request to /secret/descriptor/{secretName} (requires write permission)

### Accessing a secret
A user with read access can retrieve the secret value by GETing /keyvault/{secretName}  
A named value can be retrieved by GETing /keyvault/{secretName}/{name}

## Maintenance
When you remove/delete all access to a secret, only the Admin role can delete the secret  
Retrieve secrets without any access by GETing /secret/maintenance/noaccess  
All secrets without any access can be delete by sending a DELETE request to /secret/maintenance/noaccess

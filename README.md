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
- Windows authentication /user/{userId}/credential/windows
- Basic authentication /user/{userId}/credential/basic

## Roles

Roles give users authorization for everything but secrets
- Admin [can execute all operations]
- UserManagement [can add/update/delete users, add credentials and roles to users]
- CreateSecret [can create new secrets]
- ListSecrets [allows a user to list their own secrets]

## Secrets

### New secret
Create new secrets by POSTing to /secret  
The user creating the secret, by default gets read/write/assign permissions for the secret

### Grant access to a secret
With the assign permission, a user can grant access to a secret  
By POSTing to /secret/{secretName}/access, access can be granted to other users

### Update a secret
Send a PUT request to /secret/{secretName} (requires write permission)

### Delete a secret
Send a DELETE request to /secret/{secretName} (requires write permission)

### Accessing a secret
A user with read access can retrieve the secret value by GETing /secret/{secretName}

## Maintenance
When you remove/delete all access to a secret, only the Admin role can delete the secret  
Retrieve secrets without any access by GETing /secret/noaccess  
All secrets without any access can be delete by sending a DELETE request to /secret/noaccess

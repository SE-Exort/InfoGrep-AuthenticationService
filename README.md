# InfoGrep Authentication Service

## To run

Execute `docker compose build && docker compose up -d`.

The service will be available at localhost:4000 and hot reload any code changes made.

## API Docs
### /login
### Input
{
    username!: string,
    password!: string
}
### Output on success
{
    error: false,
    status: 'SUCCESSFUL_AUTHENTICATION',
    data: \<the session token\>
}
### Output on failure
{
    error: true,
    status: 'INVALID_USERNAME_OR_PASSWORD'
}

### /register
### Input
{
    username!: string,
    password!: string
}
### Output on success
{
    error: false,
    status: 'USER_REGISTERED',
    data: \<session token\>
}
### Output on failure
{
    error: true,
    status: 'USER_ALREADY_EXISTS'
}

### /check
### Input
{
    sessionToken!: string
}
### Output on success
{
    error: false,
    status: 'SESSION_AUTHENTICATED',
    data: 'username of authenticated user'
}
### Output on failure
{
    error: true,
    status: 'INVALID_SESSION'
}

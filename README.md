# InfoGrep Authentication Service

## Setup
Set up a .env file in the root directory of this repo, with the following content:

```
CLIENT_ID=
CLIENT_SECRET=
DOMAIN=
APP_SECRET_KEY=
REDIRECT_URI=
FRONTEND_LOGIN_URI=<login uri of infogrep>
```

Then run `docker compose build && docker compose up -d`
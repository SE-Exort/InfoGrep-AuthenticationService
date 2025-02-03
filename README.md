# InfoGrep Authentication Service

## Setup
Set up a .env file in the root directory of this repo, with the following content:

```
CLIENT_ID=
CLIENT_SECRET=
DOMAIN=
APP_SECRET_KEY=
AUTH_MODE=<either oauth or password>
```

Then run `docker compose build && docker compose up -d`
# Notes

## Setup configuration

    firebase functions:config:set \
            credential.client_email="${GOOGLE_APPLICATION_CREDENTIAL_CLIENT_EMAIL}"
            strava.client_id="${STRAVA_CLIENT_ID}" \
            strava.client_secret="${STRAVA_CLIENT_SECRET}"

## Pull configuration to use locally

    firebase functions:config:get > functions/.runtimeconfig.json
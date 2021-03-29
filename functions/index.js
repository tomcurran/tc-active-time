/* eslint-disable valid-jsdoc */
/* eslint-disable require-jsdoc */
'use strict';

const functions = require('firebase-functions');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const admin = require('firebase-admin');
// @ts-ignore
const serviceAccount = require('./service-account.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const OAUTH_REDIRECT_URI = `https://${process.env.GCLOUD_PROJECT}.firebaseapp.com/popup.html`;
// const OAUTH_REDIRECT_URI = 'http://localhost:5000/popup.html';
const OAUTH_SCOPES = 'activity:read';

/*
 * Creates a configured simple-oauth2 client for Strava.
 */
function stravaOAuth2Client() {
  const credentials = {
    client: {
      id: functions.config().strava.client_id,
      secret: functions.config().strava.client_secret,
    },
    auth: {
      tokenHost: 'https://www.strava.com',
      tokenPath: '/oauth/token',
    },
  };
  const {AuthorizationCode} = require('simple-oauth2');
  return new AuthorizationCode(credentials);
}

/**
 * Redirects the User to the Strava authentication consent screen. Also the 'state' cookie is set for later state
 * verification.
 */
exports.redirect = functions.https.onRequest((req, res) => {
  const oauth2 = stravaOAuth2Client();

  cookieParser()(req, res, () => {
    const state = req.cookies.__session || crypto.randomBytes(20).toString('hex');
    functions.logger.log('Setting verification state', state);
    res.cookie('__session', state.toString(), {
      maxAge: 3600000,
      secure: true,
      httpOnly: true,
    });
    const redirectUri = oauth2.authorizeURL({
      redirect_uri: OAUTH_REDIRECT_URI,
      scope: OAUTH_SCOPES,
      state: state,
    });
    functions.logger.log('Redirecting to', redirectUri);
    res.redirect(redirectUri);
  });
});

/**
 * Exchanges a given Strava auth code passed in the 'code' URL query parameter for a Firebase auth token.
 * The request also needs to specify a 'state' query parameter which will be checked against the 'state' cookie.
 * The Firebase custom auth token, display name, photo URL and Strava acces token are sent back in a JSONP callback
 * function with function name defined by the 'callback' query parameter.
 */
exports.token = functions.https.onRequest(async (req, res) => {
  const oauth2 = stravaOAuth2Client();

  try {
    return cookieParser()(req, res, async () => {
      try {
        const cookieState = req.cookies.__session;
        functions.logger.log('Received verification state', cookieState);
        functions.logger.log('Received state', req.query.state);
        if (!cookieState) {
          throw new Error('State cookie not set or expired. Maybe you took too long to authorize. Please try again.');
        } else if (cookieState !== req.query.state) {
          throw new Error('State validation failed');
        }
        functions.logger.log('Received auth code', req.query.code);
        const results = await oauth2.getToken({
          code: req.query.code,
          client_id: functions.config().strava.client_id,
          client_secret: functions.config().strava.client_secret,
        });
        functions.logger.log('Auth code exchange result received', JSON.parse(JSON.stringify(results)));

        // We have an Strava access token and the user identity now.
        const stravaUserID = results.token.athlete.id;
        const profilePic = results.token.athlete.profile;
        const userName = results.token.athlete.firstname + ' ' + results.token.athlete.lastname;

        // Create a Firebase account and get the Custom Auth Token.
        const token = JSON.parse(JSON.stringify(results));
        delete token.athlete;
        const firebaseToken = await createFirebaseAccount(stravaUserID, userName, profilePic, token);
        // Serve an HTML page that signs the user in and updates the user profile.
        return res.jsonp({token: firebaseToken});
      } catch (error) {
        functions.logger.error(error);
        return res.jsonp({
          error: error.toString(),
        });
      }
    });
  } catch (error) {
    functions.logger.error(error);
    return res.jsonp({
      error: error.toString(),
    });
  }
});

/**
 * Creates a Firebase account with the given user profile and returns a custom auth token allowing
 * signing-in this account.
 * Also saves the token to the firestore at /users/$uid
 *
 * @return {Promise<string>} The Firebase custom auth token in a promise.
 */
async function createFirebaseAccount(stravaID, displayName, photoURL, token) {
  // The UID we'll assign to the user.
  const uid = `strava:${stravaID}`;

  // Save the tokens
  const databaseTask = admin.firestore().collection('users').doc(uid).set({token});

  // Create or update the user account.
  const userCreationTask = admin.auth().updateUser(uid, {
    displayName: displayName,
    photoURL: photoURL,
  }).catch((error) => {
    // If user does not exists we create it.
    if (error.code === 'auth/user-not-found') {
      return admin.auth().createUser({
        uid: uid,
        displayName: displayName,
        photoURL: photoURL,
      });
    }
    throw error;
  });

  // Wait for all async task to complete then generate and return a custom auth token.
  await Promise.all([userCreationTask, databaseTask]);
  // Create a Firebase custom auth token.
  const customToken = await admin.auth().createCustomToken(uid);
  functions.logger.log('Created custom token', {uid: uid, customToken: customToken});
  return customToken;
}

exports.helloWorld = functions.https.onRequest((request, response) => {
  functions.logger.info('Hello logs!', {structuredData: true});
  response.send('Hello from Firebase!');
});

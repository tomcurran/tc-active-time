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
      sameSite: 'strict',
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

// exports.test2 = functions.firestore.document('users/{userId}/activities/{activityId}')
//     .onWrite(async (change, context) => {
//       functions.logger.log('test2', {userId: context.params.userId, activityId: context.params.activityId});
//       // handle adds, updates & deletes
//       await updateUserStats(context.params.userId);
//       return null;
//     });

async function updateUserStats(userId) {
  const db = admin.firestore();
  const userRef = db.collection('users').doc(userId);
  const activitiesRef = userRef.collection('activities');
  const summariesRef = userRef.collection('summaries');
  await db.runTransaction(async (transaction) => {
    const activitiesSnapshot = await transaction.get(activitiesRef);
    const weeklySummaries = activitiesSnapshot.docs.reduce(function(accumulator, activityDoc) {
      const activity = activityDoc.data();
      const activityWeek = getMonday(activity.startDateLocal.toDate()).setHours(0, 0, 0, 0);
      const itemIndex = accumulator.findIndex((item) => item.week == activityWeek);
      const item = itemIndex == -1 ? {week: activityWeek} : accumulator[itemIndex];
      item[activity.type] = (item[activity.type] || 0) + activity.movingTime;
      accumulator[itemIndex == -1 ? accumulator.length : itemIndex] = item;
      return accumulator;
    }, []);
    const summariesSnapshot = await summariesRef.get();
    summariesSnapshot.docs.forEach((doc) => {
      transaction.delete(doc.ref);
    });
    weeklySummaries.forEach((weekSummary) => {
      const activityDocRef = summariesRef.doc(`${weekSummary.week}`);
      transaction.set(activityDocRef, {
        runTime: weekSummary.Run || 0 + weekSummary.VirtualRun || 0,
        rideTime: weekSummary.Ride || 0 + weekSummary.VirtualRide || 0 + weekSummary.EBikeRide || 0,
        walkTime: weekSummary.Walk || 0 + weekSummary.Hike || 0,
        week: admin.firestore.Timestamp.fromMillis(weekSummary.week),
      });
    });
  });
}

// https://stackoverflow.com/a/4156516
function getMonday(d) {
  d = new Date(d);
  const day = d.getDay();
  const diff = d.getDate() - day + (day == 0 ? -6 : 1); // adjust when day is sunday
  return new Date(d.setDate(diff));
}

exports.test = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('failed-precondition', 'The function must be called while authenticated.');
  }

  try {
    const uid = context.auth.uid;

    const axios = require('axios');
    const axiosApiInstance = axios.create();

    axiosApiInstance.interceptors.request.use(async (config) => {
      const accessToken = await getAccessToken(uid);
      config.headers.Authorization = `Bearer ${accessToken}`;
      return config;
    }, (error) => Promise.reject(error));

    axiosApiInstance.interceptors.response.use(
        (response) => response,
        async (error) => {
          const originalRequest = error.config;
          if (error.response.status === 403 && !originalRequest._retry) {
            originalRequest._retry = true;
            const accessToken = await refreshAccessToken(uid);
            axiosApiInstance.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
            return axiosApiInstance(originalRequest);
          }
          return Promise.reject(error);
        });

    // gets activities last week & this week - date represents end of sunday, one week ago
    const date = new Date();
    date.setHours(23, 59, 59, 999);
    const afterMilliseconds = date.setDate(date.getDate() - date.getDay() + (date.getDay() == 0 ? -6 : 1) - 7);
    const after = Math.round(afterMilliseconds / 1000);

    const activities = [];
    let page = 0;
    let getActivitiesResponse;
    do {
      page++;
      getActivitiesResponse = await axiosApiInstance.get('https://www.strava.com/api/v3/athlete/activities', {
        params: {
          after: after,
          page: page,
          per_page: 200,
        },
      });
      activities.push(...getActivitiesResponse.data);
    } while (getActivitiesResponse.data.length);

    const db = admin.firestore();
    const batch = db.batch();
    const userDocRef = db.collection('users').doc(uid);
    for (const activity of activities) {
      const activityDocRef = userDocRef.collection('activities').doc(`strava:${activity.id}`);
      batch.set(activityDocRef, {
        athleteId: activity.athlete.id,
        movingTime: activity.moving_time,
        type: activity.type,
        startDateLocal: admin.firestore.Timestamp.fromDate(new Date(activity.start_date_local)),
      });
    }
    await batch.commit();

    await updateUserStats(uid);

    return {
      uid: uid,
      response: activities,
    };
  } catch (error) {
    functions.logger.error(error);
    throw new functions.https.HttpsError('internal', 'Error');
  }
});

async function getAccessToken(uid) {
  const userDocRef = admin.firestore().collection('users').doc(uid);
  const userData = (await userDocRef.get()).data();
  let token = stravaOAuth2Client().createToken(userData.token);
  functions.logger.log('Token', JSON.parse(JSON.stringify(token)));

  if (token.expired(5 * 60)) {
    functions.logger.log('Refreshing token');
    const refreshParams = {
      client_id: functions.config().strava.client_id,
      client_secret: functions.config().strava.client_secret,
    };
    token = await token.refresh(refreshParams);
    const jsonToken = JSON.parse(JSON.stringify(token));
    await userDocRef.update({token: jsonToken});
    functions.logger.log('Token', jsonToken);
  }

  return token.token.access_token;
}

async function refreshAccessToken(uid) {
  functions.logger.log('Refreshing token');
  const userDocRef = admin.firestore().collection('users').doc(uid);
  const userData = (await userDocRef.get()).data();
  let token = stravaOAuth2Client().createToken(userData.token);
  const refreshParams = {
    client_id: functions.config().strava.client_id,
    client_secret: functions.config().strava.client_secret,
  };
  token = await token.refresh(refreshParams);
  const jsonToken = JSON.parse(JSON.stringify(token));
  await userDocRef.update({token: jsonToken});
  functions.logger.log('Token', jsonToken);
  return token.token.access_token;
}

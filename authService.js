/**
 * Auth service
 * OAUTH 2 strategy
 * https://tools.ietf.org/html/rfc6749
 * @singleton
 */

/**
 * Access token response data
 * @typedef {Object} AccessToken
 * @property {string} access_token
 * @property {string=} refresh_token
 * @property {number} expires_in
 * @property {string=} state
 */

const Service = require('./../../core/Service');
const Exception = require('./../../core/Exception');
const H = require('./../../helpers/index');
const clientsRepository = require('./../repositories/clientsRepository');
const usersRepository = require('./../repositories/usersRepository');
const sessionsRepository = require('./../repositories/sessionsRepository');

/**
 * redirect_uri for public clients that have empty one
 * @const {string} PUBLIC_REDIRECT_URI
 */
const PUBLIC_REDIRECT_URI = '/auth/redirect';

const authService = new Service({

    /**
     * get session
     * @param {Object} params
     * @param {string} params.access_token
     * @return {Promise<Session>} - session data
     */
    getSession({access_token}) {

        return sessionsRepository.getSession(access_token);
    },

    /**
     * for internal clients
     * grant_type: password
     * create token by user credentials
     * @param {Object} params
     * @param {number} params.client_id
     * @param {string} params.client_secret
     * @param {string} params.login
     * @param {string} params.password
     * @return {Promise<AccessToken>}
     */
    createTokenByUser(params) {
        const {client_id, client_secret, login, password} = params;

        return Promise.all([
                clientsRepository.getByIdSecret(client_id, client_secret),
                usersRepository.getByLoginPassword(login, password)
            ])
            .then(([client, user]) => {
                if (client === null || user === null) {
                    throw new Exception(401);
                }

                if (client.type !== 'internal') {
                    throw new Exception(403);
                }

                return sessionsRepository.addSession(client, user);
            })
            .then((session) => {

                return {
                    access_token: session.access_token,
                    token_type: 'bearer',
                    refresh_token: session.refresh_token,
                    expires_in: session.expires_in
                };
            });
    },

    /**
     * for internal clients
     * grant_type: client_credentials
     * create token by client credentials
     * @param {Object} params
     * @param {number} params.client_id
     * @param {string} params.client_secret
     * @return {Promise<AccessToken>}
     */
    createTokenByClient({client_id, client_secret}) {

        return clientsRepository.getByIdSecret(client_id, client_secret)
            .then((client) => {
                if (client === null) {
                    throw new Exception(401);
                }

                if (client.type !== 'internal') {
                    throw new Exception(403);
                }

                return sessionsRepository.addSession(client);
            })
            .then((session) => {

                return {
                    access_token: session.access_token,
                    token_type: 'bearer',
                    refresh_token: session.refresh_token,
                    expires_in: session.expires_in
                };
            });
    }

});

module.exports = authService;
'use strict';

const winston = require('winston');
const passport = require('passport');
const nconf = require('nconf');
const path = require('path');
const util = require('util');

const meta = require('../meta');
const user = require('../user');
const groups = require('../groups');
const topics = require('../topics');
const privileges = require('../privileges');
const privilegeHelpers = require('../privileges/helpers');
const plugins = require('../plugins');
const helpers = require('./helpers');
const auth = require('../routes/authentication');
const writeRouter = require('../routes/write');
const accountHelpers = require('../controllers/accounts/helpers');

const controllers = {
	helpers: require('../controllers/helpers'),
	authentication: require('../controllers/authentication'),
};

const passportAuthenticateAsync = function (req, res) {
	return new Promise((resolve, reject) => {
		passport.authenticate('core.api', (err, user) => {
			if (err) {
				reject(err);
			} else {
				resolve(user);
				res.on('finish', writeRouter.cleanup.bind(null, req));
			}
		})(req, res);
	});
};

module.exports = function (middleware) {
	async function authenticate(req, res) {
		if (await handleAPIAuthentication(req, res)) {
			console.log('Ben C');
			return true;
		}

		if (req.loggedIn) {
			console.log('Ben C');
			return true;
		}

		if (req.headers.hasOwnProperty('authorization')) {
			console.log('Ben C');
			return await handleAuthorizationHeader(req, res);
		}

		await handlePluginHooks(req, res);

		if (!res.headersSent) {
			auth.setAuthVars(req);
		}
		console.log('Ben C');
		return !res.headersSent;
	}

	async function handleAPIAuthentication(req, res) {
		if (res.locals.isAPI && (req.loggedIn || !req.headers.hasOwnProperty('authorization'))) {
			await middleware.applyCSRFasync(req, res);
			return true;
		}
		return false;
	}

	async function handleAuthorizationHeader(req, res) {
		const user = await passportAuthenticateAsync(req, res);
		if (!user) {
			return true;
		}

		if (user.hasOwnProperty('uid')) {
			return await finishLogin(req, user);
		}

		if (user.hasOwnProperty('master') && user.master === true) {
			return await handleMasterToken(req, user);
		}

		winston.warn('[api/authenticate] Unable to find user after verifying token');
		return true;
	}

	async function handleMasterToken(req, user) {
		if (req.body.hasOwnProperty('_uid') || req.query.hasOwnProperty('_uid')) {
			user.uid = req.body._uid || req.query._uid;
			delete user.master;
			return await finishLogin(req, user);
		}

		throw new Error('[[error:api.master-token-no-uid]]');
	}

	async function handlePluginHooks(req, res) {
		await plugins.hooks.fire('response:middleware.authenticate', {
			req: req,
			res: res,
			next: function () {}, // no-op for backwards compatibility
		});
	}

	async function finishLogin(req, user) {
		const loginAsync = util.promisify(req.login).bind(req);
		await loginAsync(user, { keepSessionInfo: true });
		await controllers.authentication.onSuccessfulLogin(req, user.uid, false);
		req.uid = parseInt(user.uid, 10);
		req.loggedIn = req.uid > 0;
		return true;
	}

	middleware.authenticateRequest = helpers.try(async (req, res, next) => {
		const { skip } = await plugins.hooks.fire('filter:middleware.authenticate', {
			skip: {
				post: ['/api/v3/utilities/login'],
			},
		});

		const mountedPath = path.join(req.baseUrl, req.path).replace(nconf.get('relative_path'), '');
		const method = req.method.toLowerCase();
		if (skip[method] && skip[method].includes(mountedPath)) {
			return next();
		}

		if (!await authenticate(req, res)) {
			return;
		}
		next();
	});

	middleware.ensureSelfOrGlobalPrivilege = helpers.try(async (req, res, next) => {
		await ensureSelfOrMethod(user.isAdminOrGlobalMod, req, res, next);
	});

	middleware.ensureSelfOrPrivileged = helpers.try(async (req, res, next) => {
		await ensureSelfOrMethod(user.isPrivileged, req, res, next);
	});

	async function ensureSelfOrMethod(method, req, res, next) {
		if (!req.loggedIn) {
			return controllers.helpers.notAllowed(req, res);
		}
		if (req.uid === parseInt(res.locals.uid, 10)) {
			return next();
		}
		const allowed = await method(req.uid);
		if (!allowed) {
			return controllers.helpers.notAllowed(req, res);
		}

		return next();
	}

	middleware.canViewUsers = helpers.try(async (req, res, next) => {
		if (parseInt(res.locals.uid, 10) === req.uid) {
			return next();
		}
		const canView = await privileges.global.can('view:users', req.uid);
		if (canView) {
			return next();
		}
		controllers.helpers.notAllowed(req, res);
	});

	middleware.canViewGroups = helpers.try(async (req, res, next) => {
		const canView = await privileges.global.can('view:groups', req.uid);
		if (canView) {
			return next();
		}
		controllers.helpers.notAllowed(req, res);
	});

	middleware.canChat = helpers.try(async (req, res, next) => {
		const canChat = await privileges.global.can(['chat', 'chat:privileged'], req.uid);
		if (canChat.includes(true)) {
			return next();
		}
		controllers.helpers.notAllowed(req, res);
	});

	middleware.checkAccountPermissions = helpers.try(async (req, res, next) => {
		if (!req.loggedIn) {
			return controllers.helpers.notAllowed(req, res);
		}

		if (!['uid', 'userslug'].some(param => req.params.hasOwnProperty(param))) {
			return controllers.helpers.notAllowed(req, res);
		}

		const uid = req.params.uid || await user.getUidByUserslug(req.params.userslug);
		let allowed = await privileges.users.canEdit(req.uid, uid);
		if (allowed) {
			return next();
		}

		if (/user\/.+\/info$/.test(req.path)) {
			allowed = await privileges.global.can('view:users:info', req.uid);
		}
		if (allowed) {
			return next();
		}

		controllers.helpers.notAllowed(req, res);
	});

	middleware.redirectToAccountIfLoggedIn = helpers.try(async (req, res, next) => {
		if (req.session.forceLogin || req.uid <= 0) {
			return next();
		}
		const userslug = await user.getUserField(req.uid, 'userslug');
		controllers.helpers.redirect(res, `/user/${userslug}`);
	});

	middleware.redirectUidToUserslug = helpers.try(async (req, res, next) => {
		const uid = parseInt(req.params.uid, 10);
		if (uid <= 0) {
			return next();
		}
		const [canView, userslug] = await Promise.all([
			privileges.global.can('view:users', req.uid),
			user.getUserField(uid, 'userslug'),
		]);

		if (!userslug || (!canView && req.uid !== uid)) {
			return next();
		}
		const path = req.url.replace(/^\/api/, '')
			.replace(`/uid/${uid}`, () => `/user/${userslug}`);
		controllers.helpers.redirect(res, path, true);
	});

	middleware.redirectMeToUserslug = helpers.try(async (req, res) => {
		const userslug = await user.getUserField(req.uid, 'userslug');
		if (!userslug) {
			return controllers.helpers.notAllowed(req, res);
		}
		const path = req.url.replace(/^(\/api)?\/me/, () => `/user/${userslug}`);
		controllers.helpers.redirect(res, path);
	});

	middleware.redirectToHomeIfBanned = helpers.try(async (req, res, next) => {
		if (req.loggedIn) {
			const canLoginIfBanned = await user.bans.canLoginIfBanned(req.uid);
			if (!canLoginIfBanned) {
				req.logout(() => {
					res.redirect('/');
				});
				return;
			}
		}

		next();
	});

	middleware.requireUser = function (req, res, next) {
		if (req.loggedIn) {
			return next();
		}

		res.status(403).render('403', { title: '[[global:403.title]]' });
	};

	middleware.buildAccountData = async (req, res, next) => {
		const lowercaseSlug = req.params.userslug.toLowerCase();
		if (req.params.userslug !== lowercaseSlug) {
			if (res.locals.isAPI) {
				req.params.userslug = lowercaseSlug;
			} else {
				const newPath = req.path.replace(new RegExp(`/${req.params.userslug}`), () => `/${lowercaseSlug}`);
				return res.redirect(`${nconf.get('relative_path')}${newPath}`);
			}
		}

		res.locals.userData = await accountHelpers.getUserDataByUserSlug(req.params.userslug, req.uid, req.query);
		if (!res.locals.userData) {
			return next('route');
		}
		next();
	};

	middleware.registrationComplete = async function registrationComplete(req, res, next) {
		const path = req.path.startsWith('/api/') ? req.path.replace('/api', '') : req.path;

		if (meta.config.requireEmailAddress && await requiresEmailConfirmation(req)) {
			req.session.registration = {
				...req.session.registration,
				uid: req.uid,
				updateEmail: true,
			};
		}

		if (!req.session.hasOwnProperty('registration')) {
			return setImmediate(next);
		}

		const { allowed } = await plugins.hooks.fire('filter:middleware.registrationComplete', {
			allowed: ['/register/complete', '/confirm/'],
		});
		if (allowed.includes(path) || allowed.some(p => path.startsWith(p))) {
			return setImmediate(next);
		}

		req.session.registration.uid = req.session.registration.uid || req.uid;

		controllers.helpers.redirect(res, '/register/complete');
	};

	async function requiresEmailConfirmation(req) {
		if (req.uid <= 0) {
			return false;
		}

		const [confirmed, isAdmin] = await Promise.all([
			groups.isMember(req.uid, 'verified-users'),
			user.isAdministrator(req.uid),
		]);
		if (confirmed || isAdmin) {
			return false;
		}

		let cid;
		let privilege;
		if (req.params.hasOwnProperty('category_id')) {
			cid = req.params.category_id;
			privilege = 'read';
		} else if (req.params.hasOwnProperty('topic_id')) {
			cid = await topics.getTopicField(req.params.topic_id, 'cid');
			privilege = 'topics:read';
		} else {
			return false;
		}

		const [registeredAllowed, verifiedAllowed] = await Promise.all([
			privilegeHelpers.isAllowedTo([privilege], 'registered-users', cid),
			privilegeHelpers.isAllowedTo([privilege], 'verified-users', cid),
		]);

		return !registeredAllowed.pop() && verifiedAllowed.pop();
	}
};

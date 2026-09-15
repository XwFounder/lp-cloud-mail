import BizError from '../error/biz-error';
import userService from './user-service';
import emailUtils from '../utils/email-utils';
import { isDel, settingConst, userConst } from '../const/entity-const';
import JwtUtils from '../utils/jwt-utils';
import { v4 as uuidv4 } from 'uuid';
import KvConst from '../const/kv-const';
import constant from '../const/constant';
import userContext from '../security/user-context';
import verifyUtils from '../utils/verify-utils';
import accountService from './account-service';
import settingService from './setting-service';
import saltHashUtils from '../utils/crypto-utils';
import cryptoUtils from '../utils/crypto-utils';
import turnstileService from './turnstile-service';
import roleService from './role-service';
import regKeyService from './reg-key-service';
import dayjs from 'dayjs';
import { toUtc } from '../utils/date-uitil';
import { t } from '../i18n/i18n.js';
import verifyRecordService from './verify-record-service';

const loginService = {

	async register(c, params, oauth = false) {

		const { email, password, token, code } = params;

		let { regKey, register, registerVerify, regVerifyCount, minEmailPrefix, emailPrefixFilter } = await settingService.query(c)

		if (oauth) {
			registerVerify = settingConst.registerVerify.CLOSE;
			register = settingConst.register.OPEN;
		}

		if (register === settingConst.register.CLOSE) {
			throw new BizError(t('regDisabled'));
		}

		if (!verifyUtils.isEmail(email)) {
			throw new BizError(t('notEmail'));
		}

		if (emailUtils.getName(email).length < minEmailPrefix) {
			throw new BizError(t('minEmailPrefix', { msg: minEmailPrefix } ));
		}

		if (emailPrefixFilter.some(content => emailUtils.getName(email).includes(content)))  {
			throw new BizError(t('banEmailPrefix'));
		}

		if (emailUtils.getName(email).length > 64) {
			throw new BizError(t('emailLengthLimit'));
		}

		if (password.length > 30) {
			throw new BizError(t('pwdLengthLimit'));
		}

		if (password.length < 6) {
			throw new BizError(t('pwdMinLength'));
		}

		if (!c.env.domain.includes(emailUtils.getDomain(email))) {
			throw new BizError(t('notEmailDomain'));
		}

		let type = null;
		let regKeyId = 0

		if (regKey === settingConst.regKey.OPEN) {
			const result = await this.handleOpenRegKey(c, regKey, code)
			type = result?.type
			regKeyId = result?.regKeyId
		}

		if (regKey === settingConst.regKey.OPTIONAL) {
			const result = await this.handleOpenOptional(c, regKey, code)
			type = result?.type
			regKeyId = result?.regKeyId
		}

		const accountRow = await accountService.selectByEmailIncludeDel(c, email);

		if (accountRow && accountRow.isDel === isDel.DELETE) {
			throw new BizError(t('isDelUser'));
		}

		if (accountRow) {
			throw new BizError(t('isRegAccount'));
		}

		let defType = null

		if (!type) {
			const roleRow = await roleService.selectDefaultRole(c);
			defType = roleRow.roleId
		}


		const roleRow = await roleService.selectById(c, type || defType);

		if(!roleService.hasAvailDomainPerm(roleRow.availDomain, email)) {

			if (type) {
				throw new BizError(t('noDomainPermRegKey'),403)
			}

			if (defType) {
				throw new BizError(t('noDomainPermReg'),403)
			}

		}

		let regVerifyOpen = false

		if (registerVerify === settingConst.registerVerify.OPEN) {
			regVerifyOpen = true
			await turnstileService.verify(c,token)
		}

		if (registerVerify === settingConst.registerVerify.COUNT) {
			regVerifyOpen = await verifyRecordService.isOpenRegVerify(c, regVerifyCount);
			if (regVerifyOpen) {
				await turnstileService.verify(c,token)
			}
		}

		const { salt, hash } = await saltHashUtils.hashPassword(password);

		const userId = await userService.insert(c, { email, regKeyId,password: hash, salt, type: type || defType });

		await accountService.insert(c, { userId: userId, email, name: emailUtils.getName(email) });

		await userService.updateUserInfo(c, userId, true);

		if (regKey !== settingConst.regKey.CLOSE && type) {
			await regKeyService.reduceCount(c, code, 1);
		}

		if (registerVerify === settingConst.registerVerify.COUNT && !regVerifyOpen) {
			const row = await verifyRecordService.increaseRegCount(c);
			return {regVerifyOpen: row.count >= regVerifyCount}
		}

		return {regVerifyOpen}

	},

	async registerVerify() {

	},

	async handleOpenRegKey(c, regKey, code) {

		if (!code) {
			throw new BizError(t('emptyRegKey'));
		}

		const regKeyRow = await regKeyService.selectByCode(c, code);

		if (!regKeyRow) {
			throw new BizError(t('notExistRegKey'));
		}

		if (regKeyRow.count <= 0) {
			throw new BizError(t('noRegKeyCount'));
		}

		const today = toUtc().tz('Asia/Shanghai').startOf('day')
		const expireTime = toUtc(regKeyRow.expireTime).tz('Asia/Shanghai').startOf('day');

		if (expireTime.isBefore(today)) {
			throw new BizError(t('regKeyExpire'));
		}

		return { type: regKeyRow.roleId, regKeyId: regKeyRow.regKeyId };
	},

	async handleOpenOptional(c, regKey, code) {

		if (!code) {
			return null
		}

		const regKeyRow = await regKeyService.selectByCode(c, code);

		if (!regKeyRow) {
			return null
		}

		const today = toUtc().tz('Asia/Shanghai').startOf('day')
		const expireTime = toUtc(regKeyRow.expireTime).tz('Asia/Shanghai').startOf('day');

		if (regKeyRow.count <= 0 || expireTime.isBefore(today)) {
			return null
		}

		return { type: regKeyRow.roleId, regKeyId: regKeyRow.regKeyId };
	},

	async login(c, params, noVerifyPwd = false) {
		let { email, password } = params;

		// ============================
		// 1. 基础参数校验
		// ============================
		if ((!email || !password) && !noVerifyPwd) {
			throw new BizError(t('emailAndPwdEmpty'));
		}


		// ============================
		// 2. IP
		// ============================
		const clientIp =
			c.req.header('cf-connecting-ip') || 'unknown-ip';
	// ==================== IP 登录频率限制 ====================

		const rateLimitKey = `rate_limit:login:${clientIp}`;

		let requests = parseInt(
			await c.env.kv.get(rateLimitKey) || '0',
			10
		);

		if (!Number.isFinite(requests) || requests < 0) {
			requests = 0;
		}

		if (requests >= 5) {
			throw new BizError(
				'请求过于频繁，请 1 分钟后再试'
			);
		}

		await c.env.kv.put(
			rateLimitKey,
			String(requests + 1),
			{
				expirationTtl: 60
			}
		);
		// ============================
		// 3. 规范化邮箱
		// ============================
		if (email) {
			email = String(email).trim().toLowerCase();
		}

		// ============================
		// 4. IP + 邮箱失败计数
		// ============================
		const failKey = `login_fail:${clientIp}:${email || 'unknown-email'}`;

		let failCount = parseInt(
			await c.env.kv.get(failKey) || '0',
			10
		);

		// 防止 KV 异常数据
		if (!Number.isFinite(failCount) || failCount < 0) {
			failCount = 0;
		}

		// ============================
		// 5. 检查是否已经被锁定
		// ============================
		if (!noVerifyPwd && failCount >= 5) {
			throw new BizError(
				'登录失败次数过多，请 15 分钟后再试'
			);
		}

		// ============================
		// 6. 查询用户
		// ============================
		const userRow =
			await userService.selectByEmailIncludeDel(c, email);

		// ============================
		// 7. 用户不存在
		// ============================
		if (!userRow) {
			if (!noVerifyPwd) {
				failCount += 1;

				await c.env.kv.put(
					failKey,
					String(failCount),
					{
						expirationTtl: 900
					}
				);
			}

			throw new BizError(t('notExistUser'));
		}

		// ============================
		// 8. 用户已删除
		// ============================
		if (userRow.isDel === isDel.DELETE) {
			throw new BizError(t('isDelUser'));
		}

		// ============================
		// 9. 用户已封禁
		// ============================
		if (userRow.status === userConst.status.BAN) {
			throw new BizError(t('isBanUser'));
		}

		// ============================
		// 10. 验证密码
		// ============================
		if (!noVerifyPwd) {
			const isPwdValid =
				await cryptoUtils.verifyPassword(
					password,
					userRow.salt,
					userRow.password
				);

			// ============================
			// 11. 密码错误
			// ============================
			if (!isPwdValid) {
				failCount += 1;

				await c.env.kv.put(
					failKey,
					String(failCount),
					{
						expirationTtl: 900
					}
				);

				// 第5次错误后，下一次请求直接进入锁定状态
				if (failCount >= 5) {
					throw new BizError(
						'密码错误次数过多，请 15 分钟后再试'
					);
				}

				throw new BizError(t('IncorrectPwd'));
			}
		}

		// ============================
		// 12. 登录成功，清除失败记录
		// ============================
		if (!noVerifyPwd && failCount > 0) {
			await c.env.kv.delete(failKey);
		}

		// ============================
		// 13. 生成 UUID
		// ============================
		const uuid = uuidv4();

		// ============================
		// 14. 生成 JWT
		// ============================
		const jwt = await JwtUtils.generateToken(
			c,
			{
				userId: userRow.userId,
				token: uuid
			}
		);

		// ============================
		// 15. 获取已有认证信息
		// ============================
		let authInfo = await c.env.kv.get(
			KvConst.AUTH_INFO + userRow.userId,
			{
				type: 'json'
			}
		);

		// ============================
		// 16. 更新 Token
		// ============================
		if (
			authInfo &&
			authInfo.user &&
			authInfo.user.email === userRow.email
		) {
			if (!Array.isArray(authInfo.tokens)) {
				authInfo.tokens = [];
			}

			if (authInfo.tokens.length > 10) {
				authInfo.tokens.shift();
			}

			authInfo.tokens.push(uuid);
		} else {
			authInfo = {
				tokens: [uuid],
				user: userRow,
				refreshTime: dayjs().toISOString()
			};
		}

		// ============================
		// 17. 更新用户信息
		// ============================
		await userService.updateUserInfo(
			c,
			userRow.userId
		);

		// ============================
		// 18. 保存认证信息
		// ============================
		await c.env.kv.put(
			KvConst.AUTH_INFO + userRow.userId,
			JSON.stringify(authInfo),
			{
				expirationTtl: constant.TOKEN_EXPIRE
			}
		);

		// ============================
		// 19. 返回 JWT
		// ============================
		return jwt;
	},

	async logout(c, userId) {
		const token =userContext.getToken(c);
		const authInfo = await c.env.kv.get(KvConst.AUTH_INFO + userId, { type: 'json' });
		const index = authInfo.tokens.findIndex(item => item === token);
		authInfo.tokens.splice(index, 1);
		await c.env.kv.put(KvConst.AUTH_INFO + userId, JSON.stringify(authInfo));
	}

};

export default loginService;

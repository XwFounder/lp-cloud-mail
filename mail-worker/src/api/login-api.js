import app from '../hono/hono';
import loginService from '../service/login-service';
import result from '../model/result';
import userContext from '../security/user-context';

app.post('/login', async (c) => {
    // 1. 获取客户端 IP
    const clientIp = c.req.header('cf-connecting-ip') || 'unknown-ip';

    // 2. IP 登录频率限制 Key
    const rateLimitKey = `rate_limit:login:${clientIp}`;

    // 3. 获取当前 1 分钟请求次数
    let requests = parseInt(
        await c.env.kv.get(rateLimitKey) || '0',
        10
    );

    // 防止 KV 中出现异常数据
    if (!Number.isFinite(requests) || requests < 0) {
        requests = 0;
    }

    // 4. 1 分钟最多 5 次
    if (requests >= 5) {
        throw new BizError('请求过于频繁，请 1 分钟后再试');
    }

    // 5. 请求次数 +1
    await c.env.kv.put(
        rateLimitKey,
        String(requests + 1),
        {
            expirationTtl: 60
        }
    );

    // 6. 获取登录参数
    const params = await c.req.json();

    // 7. 执行登录
    const token = await loginService.login(c, params);

    return c.json(
        result.ok({
            token: token
        })
    );
});

app.post('/register', async (c) => {
	const jwt = await loginService.register(c, await c.req.json());
	return c.json(result.ok(jwt));
});

app.delete('/logout', async (c) => {
	await loginService.logout(c, userContext.getUserId(c));
	return c.json(result.ok());
});


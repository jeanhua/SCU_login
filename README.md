# 四川大学教务系统统一登陆认证脚本

## 使用方法：

```
 1.调用 get_access_token(client_id: str, username: str, password: str) 方法获取 access_token
    参数有:
        client_id 客户端id，用于区分不同的网站，比如大川学堂是1371cbeda563697537f28d99b4744a973uDKtgYqL5B，具体的可以F12抓包登陆查看
        username 学号
        password 密码
2.(可选)获取到access_token后，调用 get_2FA_result(access_token: str, applicaation_key)
        applicaation_key是应用标识，具体也可抓包查看，比如大川学堂是 scdxplugin_jwt40
        返回false说明登陆成功，否则则需要二次认证(短信验证码之类的)
3.使用accesstoken重定向到对应的网站即可登陆成功，获取request的cookie即可进行各种操作
```
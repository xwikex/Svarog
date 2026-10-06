# 安全问题报告

感谢你帮助改进 Svarog 的安全性。

## 报告方式

如果 GitHub 仓库启用了 Private vulnerability reporting，请优先通过仓库的 **Security → Report a vulnerability** 私下提交。尚未配置私密渠道时，请只在公开 Issue 中描述不包含敏感数据的最小现象，并请维护者提供私密联系方式。

## 不要公开提交的数据

请勿在公开 Issue、Pull Request、截图或附件中提交：

- 真实 API Token、密码、Cookie、Authorization 请求头或私钥；
- 未脱敏的生产日志、告警原文或报告；
- `.env`、Svarog 配置文件或 SQLite 数据库；
- 客户名称、内部地址、业务数据及其他个人或企业敏感信息。

请使用最小化的虚构样例复现问题，并删除用户名、绝对路径和网络内部信息。

## 支持范围

安全报告应说明受影响版本、操作系统、Python 版本、复现步骤和预期影响。Svarog 的可信功能模块与工作台进程拥有相同权限；只有经过人工审查的自有模块属于当前支持范围。

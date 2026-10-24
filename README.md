# VeilGuard Audit

面向 Solidity 合约的本地优先安全分析网页应用。它把**可定位的规则线索**、可选的 [Slither](https://github.com/crytic/slither) 检测结果，以及**主动触发的本地 AI 复核建议**放在同一个报告界面中。

> 这是初步审查辅助工具。规则命中并不等于已证实的漏洞；未命中也不等于安全。上线前仍需测试、人工审计及适合项目风险的更深入验证。[Solidity 官方文档](https://docs.soliditylang.org/en/latest/security-considerations.html)也指出安全注意事项清单并不完整。

## 功能

- 在网页中粘贴源码或载入单个 .sol 文件，查看规则、行号、证据和修复方向。
- 检查 tx.origin、selfdestruct、delegatecall、低级 .call、unchecked、block.timestamp 等需要复核的用法。
- 可选运行本机 Slither；如果未安装或编译失败，界面会显示状态。
- 单独点击才会把源码交给本机 Ollama 模型做解释；AI 文本始终标为未经验证。
- 下载 JSON 报告。报告不包含完整源码，但**包含命中行的代码片段**，分享前应自行检查。
- 仅监听 127.0.0.1，不提供账号、数据库、遥测或云端 API 接口。

## 快速开始

需要 Python 3.10 或更新版本。必需功能不依赖第三方 Python 包。

在项目目录运行：

~~~powershell
python server.py
~~~

然后打开 [http://127.0.0.1:8765](http://127.0.0.1:8765)。点击“载入示例”即可试用。改用其他端口时运行 python server.py --port 9000。

## 可选工具

### Slither

根据 [Slither 官方安装说明](https://github.com/crytic/slither#how-to-install)安装 slither-analyzer，并配置与合约版本匹配的 Solidity 编译器。例如：

~~~powershell
python -m pip install slither-analyzer
~~~

启动网页前确认 slither --version 可用。单文件中的外部 import 不由本应用解析；有依赖的完整项目宜直接在该项目中运行 slither .。Slither 在临时目录中处理网页提交的单文件，超时为 30 秒。Slither 结果保留原检测项、影响等级、置信度及行号（如可用）。

### Ollama

安装并启动 [Ollama](https://ollama.com/download)，下载希望使用的代码模型，例如 ollama pull qwen2.5-coder:7b。界面中填入对应模型名称，完成规则扫描后再点击“请求本地 AI 分析”。本应用直连 127.0.0.1:11434 的 [Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md)；模型不存在或服务未启动时会提示错误。首次加载模型可能较慢。为了保护源码，应用拒绝名称以 :cloud 或 -cloud 结尾的 [Ollama 云端模型](https://ollama.com/blog/cloud-models)。Ollama 允许通过本地接口调用云端模型，因此如果你配置了自定义模型别名或代理服务，请自行确认它确实在本机推理。

## 隐私与安全边界

| 环节 | 数据处理 |
| --- | --- |
| 规则扫描 | 浏览器把源码发送到本机 127.0.0.1 的 Python 服务；服务在内存中扫描，不保存源码。 |
| Slither（可选） | 源码暂写入系统临时目录供本机 Slither 编译，分析结束后删除。运行中或异常中断时，操作系统临时目录可能短暂保留文件。 |
| AI 复核（可选） | 只有手动点击后才把源码及规则线索发送到本机 Ollama。应用使用直连，不读取系统代理设置。 |
| 报告导出 | 浏览器下载 JSON；不包含完整源码，可能包含证据片段和 AI 输出。 |
| 页面资源 | 全部来自项目目录，无外部脚本、字体或追踪器。 |

服务仅允许 loopback 绑定、限制输入大小（源码 256 KiB，请求 512 KiB）、校验浏览器的 Host 和 Origin，并以纯文本呈现源码及模型输出。项目未实现多用户隔离；只适合在可信的本机环境运行。

## API

- GET /api/status：Slither 是否可用，以及固定的本机 Ollama 地址。
- POST /api/scan：JSON {"source":"...", "with_slither":false}。
- POST /api/ai：JSON {"source":"...", "model":"qwen2.5-coder:7b"}；会重新计算规则线索，只返回 AI 建议。

API 不支持远程 URL、路径或仓库导入。

## 测试

~~~powershell
python -m unittest discover -s tests -v
node --check web/app.js
~~~

测试不需要安装 Slither 或 Ollama。examples/VulnerableVault.sol 是故意含风险的演示合约，**不要部署**。

## 项目结构

~~~text
scanner.py       内置保守规则与源码遮罩
integrations.py  Slither 和本地 Ollama 适配器
server.py        本机 HTTP 服务与 JSON API
web/             网页界面
tests/           扫描、适配器、API 测试
docs/            设计与实施计划
examples/        演示合约
~~~

## 许可

MIT License。欢迎提交问题、误报样例和规则改进。

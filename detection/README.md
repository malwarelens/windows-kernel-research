# Detection

本目录收录与本仓库各漏洞分析配套的**检测思路与遥测说明**：行为特征、
Sysmon / ETW / EDR 可观测点、以及误报注意事项。

目前各 CVE 的检测要点先写在各自的 `analysis.md`「检测与缓解」一节中；
当某个检测思路可复用到多个漏洞（例如 win32k 用户模式回调滥用的通用
行为特征）时，再抽取到本目录形成独立条目。

## 计划中的条目

- `win32k-callback-abuse.md` — win32k 用户模式回调滥用的通用观测点：
  进程改写自身 `PEB.KernelCallbackTable`、窗口创建过程中异常调用
  `NtUserConsoleControl`、桌面堆布局异常、data-only 提权后的令牌异常等。
- `token-anomalies.md` — data-only 提权（复制 SYSTEM 令牌类手法）在
  进程遥测中的可见痕迹与 Sysmon 的能力边界。

> 状态：占位，后续补充。检测结论以各分析文档中标注的来源与实测为准，
> 未实测的观测点会明确标注为「推测/待验证」。

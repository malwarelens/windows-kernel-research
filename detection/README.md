# Detection

本目录收录与本仓库各漏洞分析配套的**检测思路与遥测说明**：行为特征、
Sysmon / ETW / EDR 可观测点、以及误报注意事项。

目前各 CVE 的检测要点先写在各自的 `analysis.md`「检测与缓解」一节中；
当某个检测思路可复用到多个漏洞（例如 win32k 用户模式回调滥用的通用
行为特征）时，再抽取到本目录形成独立条目。

## 已有条目

- [`win32k-callback-abuse.md`](win32k-callback-abuse.md) — win32k 用户模式
  回调滥用的通用观测点：进程改写自身 `PEB.KernelCallbackTable`、窗口创建
  过程中异常调用 `NtUserConsoleControl`、桌面堆布局异常、data-only 提权
  后的令牌异常等，并给出按行为链组合判定的建议。
- [`token-anomalies.md`](token-anomalies.md) — data-only 提权在进程遥测
  中的结果痕迹：已有进程令牌原地突变、低权限父进程创建 SYSTEM 子进程、
  令牌与登录 / 服务记录互相矛盾等，并说明 Sysmon 只覆盖进程创建时刻、
  不监控令牌变更的能力边界。

> 检测结论以各分析文档中标注的来源与实测为准，未实测的观测点会
> 明确标注为「推测/待验证」。

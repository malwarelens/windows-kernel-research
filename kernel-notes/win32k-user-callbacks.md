# win32k 用户模式回调（User-Mode Callbacks）机制笔记

> 本笔记梳理 win32k 的用户模式回调机制及其为何长期是内核漏洞的富矿，
> 为本仓库的 win32k 类漏洞分析（如 CVE-2021-1732）提供背景。内容为结合
> 公开资料的自有行文，文末列出主要参考。

## 机制是什么

win32k 是 Windows 图形/窗口子系统的内核部分，负责窗口、消息、GDI 对象等。
它有一个结构性特点：**内核在执行过程中，经常需要反过来调用用户态代码**，
例如：

- 调用应用安装的钩子（WH_* hooks）与事件通知（WinEvent）；
- 窗口创建/销毁过程中向客户端要数据或让客户端分配资源
  （如 `xxxClientAllocWindowClassExtraBytes`）；
- 在内核与用户态之间搬运消息附带的数据（如 DDE 消息的拷贝进出）；
- 调用用户态的窗口过程、类过程、编辑控件逻辑等。

实现上，这套机制建立在 NT 执行体导出的 `KeUserModeCallback` 之上，
形态类似一次「反向系统调用」：

```c
NTSTATUS KeUserModeCallback(
    IN  ULONG  ApiNumber,     // 要调用的用户态函数编号
    IN  PVOID  InputBuffer,   // 入参（内核准备，放在用户栈上）
    IN  ULONG  InputLength,
    OUT PVOID  *OutputBuffer, // 回调返回值
    OUT PULONG OutputLength);
```

`ApiNumber` 是用户态回调分发表的下标。这张表本体在 user32.dll 的
`apfnDispatch` 中，其地址在进程初始化 user32 时被复制到
`PEB.KernelCallbackTable`——也就是说，**分发表位于进程自己的用户态内存里，
进程可读写**。内核每次回调，先在内核栈上保存陷阱帧（trap frame）以便
恢复上下文，再切回用户态执行指定函数，函数经 `NtCallbackReturn`
把结果送回内核，内核函数随后继续执行。

## 为什么这是漏洞富矿

### 1. 回调 = 内核执行流被用户态「暂停并接管」

回调返回之前，用户态代码可以任意运行。它可以销毁、重建、转换内核
正在操作的对象与状态——窗口被销毁、菜单被替换、窗口类型被切换
（如 CVE-2021-1732 中把窗口转成控制台类型）。如果内核函数在回调之后
**不假思索地继续使用回调前缓存的状态**（指针、索引、类型假设），就会
踩到已被更换的地基上：use-after-free、类型混淆、字段语义混淆反复
以这种形态出现。Tarjei Mandt 2011 年的经典论文《Kernel Attacks
through User-Mode Callbacks》系统性地指出了这一点：回调之后缺少对
对象与状态的重新校验（re-validation），是 win32k 的一类结构性缺陷。

### 2. 对象生命周期与引用计数复杂

win32k 的用户对象（窗口、菜单、钩子等）由会话级全局锁粗粒度保护，
对象还有 assignment locking 等历史包袱。回调期间对象被释放但内核
结构里还留着引用、或锁被递归进入导致状态不一致，都是被反复利用的点。
Mandt 的论文中 DDE 会话对象在回调后未重新校验伙伴对象即是早期实例。

### 3. 回调表本身可被用户态改写

分发表在进程 PEB 中，攻击者 hook 某个回调入口不需要任何特权——改写
自己进程的表项即可。这使得「在内核预期的回调时机插入任意用户态逻辑」
成为低门槛的标准技巧，大量 win32k 利用的第一步都是 hook
`KernelCallbackTable`（本仓库 CVE-2021-1732、CVE-2022-21882 均如此）。

### 4. 桌面堆与 tagWND：回调副作用的「放大器」

窗口对象 `tagWND` 同时存在内核桌面堆中的副本与映射到用户态的副本，
`pExtraBytes`、`cbWndExtra`、`spmenu` 等字段又横跨用户/内核两种语义
（指针 vs 偏移）。回调里对窗口状态的任何切换（普通→控制台）都会
改写这些字段的解释方式；一旦与内核的陈旧假设相撞，往往直接产出
内核堆上的越界读写原语，而 tagWND 恰好是构造任意读写的经典跳板。
历史上 CVE-2014-4113、CVE-2015-0057、CVE-2016-7255、CVE-2019-0808
等一系列 win32k 提权都与 tagWND/回调滥用有关（Unit 42 系列有汇总）。

### 5. 攻击面规模

回调点数量多（分发表有上百个条目）、涉及的历史子系统杂（DDE、剪贴板、
菜单、钩子、控制台……），且 win32k 为兼容性长期保留旧语义。微软的
对策包括：把 win32k 拆分为 win32kbase/win32kfull、给 tagWND 滥用面
加固（1703 起 SetWindowLong 默认只改用户态副本）、以及在高价值进程中
直接禁用 win32k 调用（win32k lockdown，如 Chrome 渲染进程）——但
只要回调机制存在，「回调后校验」就仍是每个 win32k 开发者函数必须
逐一做对的事情，做漏一处就是一个 CVE。这正是 1732 补丁之后还会有
21882 的土壤。

## 对防御的启示

- **补丁分析要看模式，不要只看补丁点**：同形态的回调校验缺失往往成簇
  出现，一处修复后应主动审计相邻回调路径；
- **检测抓行为模式**：进程改写自身 `KernelCallbackTable`、窗口创建
  过程中异常地进行类型转换、普通应用进程高频使用冷门的 `NtUser*`
  调用，都是比单漏洞特征更耐用的观测点（详见各 `analysis.md`
  的检测章节与 `detection/` 目录）；
- **减面优先于检测**：对不需要 GUI 的进程禁用 win32k 调用，是对
  这一整类漏洞最干净的缓解。

## 参考资料

- Tarjei Mandt, *Kernel Attacks through User-Mode Callbacks*,
  Black Hat USA 2011 / MWR Labs 白皮书（回调机制、KeUserModeCallback、
  回调后未重新校验的系统性问题）：
  https://elhacker.info/manuales/Kernel/mandt-win32k-paper.pdf
- Unit 42, *Inside Win32k Exploitation: Background on Implementations
  of Win32k and Exploitation Methodologies*（Part 1，"User-mode
  Callbacks" 一节与 tagWND 利用背景）：
  https://unit42.paloaltonetworks.com/win32k-analysis-part-1/
- Mateusz Jurczyk (j00ru), *Windows Security Hardening Through Kernel
  Address Protection*（win32k 句柄表、桌面堆与早期 win32k 加固讨论）：
  https://j00ru.vexillium.org/papers/2011/address_protection.pdf
- Unit 42, *Inside Win32k Exploitation: Analysis of CVE-2022-21882
  and CVE-2021-1732*（回调 hook + 控制台转换的现代利用实例）：
  https://unit42.paloaltonetworks.com/win32k-analysis-part-2/

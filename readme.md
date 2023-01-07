# 通过System令牌获取UIAccess

此项目用于获取UIAccess权限，它可以让你的程序窗口获得更高的Z序，比如高于任务管理器等，与屏幕键盘同层。可以用来解决制作屏幕标记/录制工具时窗口被遮挡的问题。

## 效果对比

以任务管理器为例，先打开任务管理器的”置于顶层“，它的窗口Band是`ZBID_SYSTEM_TOOLS`，高于常规窗口Band。

未启用UIAccess时，无论是否`SetWindowPos(HWND_TOPMOST)`，窗口Z序始终低于任务管理器：

![启用前](https://raw.githubusercontent.com/killtimer0/uiaccess/master/img/uia_off.gif)

启用UIAccess并调用`SetWindowPos(HWND_TOPMOST)`后，窗口Z序将高于任务管理器：

![启用后](https://raw.githubusercontent.com/killtimer0/uiaccess/master/img/uia_on.gif)

## 条件和用法

程序需要提权运行（`elevated`），因此最好设置请求管理员权限的清单，或者通过某个已提权的进程启动，否则获取不到UIAccess，函数返回值为`ERROR_NOT_FOUND`。加入头文件和源文件后，在程序的最开头调用`PrepareForUIAccess()`即可，如果设置成功则返回`ERROR_SUCCESS`，否则返回错误代码。

## 程序原理

> 相比于上一版本，修复了用户权限“替换进程令牌”关闭时UIAccess设置失败的问题；程序从启动进程3次改为了2次，而且无需启动System权限的另一个进程，免去了IPC通信的过程。

进程以管理员权限启动，然后检测自身是否具有UIAccess权限。此时还未获取权限，所以它遍历进程列表，尝试获取同一Session下`winlogon.exe`的令牌 ，并用这个令牌创建另一个具有`TokenUIAccess`的令牌，然后用它启动另一个实例。此实例检测UIAccess权限，权限已经满足，返回`ERROR_SUCCESS`，随后旧进程退出，具有权限的新进程继续运行。

## 窗口Z序的介绍

在Windows7及以下系统，直接用`SetWindowPos(HWND_TOPMOST)`可以使窗口在最上层。但从Windows8开始，微软引入了其他窗口段（Band），它们从低到高的顺序如下：

```
ZBID_DESKTOP
ZBID_IMMERSIVE_BACKGROUND
ZBID_IMMERSIVE_APPCHROME
ZBID_IMMERSIVE_MOGO
ZBID_IMMERSIVE_INACTIVEMOBODY
ZBID_IMMERSIVE_NOTIFICATION
ZBID_IMMERSIVE_EDGY
ZBID_SYSTEM_TOOLS
ZBID_LOCK（仅Windows 10）
ZBID_ABOVELOCK_UX（仅Windows 10）
ZBID_IMMERSIVE_IHM
ZBID_GENUINE_WINDOWS
ZBID_UIACCESS
```

默认的窗口段是`ZBID_DESKTOP`，这导致无论如何`SetWindowPos`，窗口的Z序始终低于设置过其他更高层段的窗口。

那么为什么不设置其他窗口段呢？

Windows中有下面这些API可以改变程序的窗口段：

```c
HWND WINAPI CreateWindowInBand(
	DWORD dwExStyle,
  	LPCWSTR lpClassName,
	LPCWSTR lpWindowName,
	DWORD dwStyle,
	int x,
	int y,
	int nWidth,
	int nHeight,
	HWND hWndParent,
	HMENU hMenu,
	HINSTANCE hInstance,
	LPVOID lpParam,
	DWORD dwBand
);
HWND WINAPI CreateWindowInBandEx(
	DWORD dwExStyle,
  	LPCWSTR lpClassName,
	LPCWSTR lpWindowName,
	DWORD dwStyle,
	int x,
	int y,
	int nWidth,
	int nHeight,
	HWND hWndParent,
	HMENU hMenu,
	HINSTANCE hInstance,
	LPVOID lpParam,
	DWORD dwBand,
	DWORD dwTypeFlags
);
BOOL WINAPI SetWindowBand(
	HWND hWnd, 
	HWND hwndInsertAfter, 
	DWORD dwBand
);
```

但调用`CreateWindowInBand(Ex)`的程序必须使用微软的证书进行数字签名，也就是说，只有Windows内置的程序才能使用这些API，任务管理器正是这么做的。而`SetWindowBand`需要调用私有API：`NtUserEnableIAMAccess`，它有一个类似句柄的参数（key），此句柄只能通过`NtUserAcquireIAMKey`获取。而`NtUserAcquireIAMKey`调用成功的条件是，调用线程必须是当前桌面线程（即调用`SetShellWindows(Ex)`的线程），而且只能获取一次，否则函数都会`ERROR_ACCESS_DENIED`，你甚至不能注入`explorer.exe`获取key，因为`explorer.exe`已经调用过一次`NtUserAcquireIAMKey`了。也就是说，只有桌面的管理者能使用`SetWindowBand`。

那有没有其他办法呢？注意到屏幕键盘（`osk.exe`）和VS的一个工具`Inspect.exe`的窗口也可以设置比任务管理器高的窗口。逆向后发现它们也不过只是`SetWindowPos(HWND_TOPMOST)`而已，最后发现是程序的清单中有一项：

```
<requestedExecutionLevel level="asInvoker" uiAccess="true"/>
```

[MSDN](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)中解释说，这个UIAccess权限用于支持无障碍服务，通过它可以在未提权的进程下访问已提权进程的窗口。出于安全考虑，如果要启用它，必须满足：

* 应用程序必须具有数字签名，可以使用与本地计算机上的受信任根证书颁发机构存储关联的数字证书进行验证。
* 应用程序必须安装在只能由管理员写入的本地文件夹中，例如`Program Files`目录。允许的目录包括：
  * `%ProgramFiles%`和它的子目录
  * `%WinDir%`和它的子目录，除了少数标准用户具有写权限的子目录。

进程令牌中就有着`TokenUIAccess`这个属性，这意味着我们在提权后，可以通过`SetTokenInformation`设置此权限，从而绕过数字签名和指定的安装路径。

但经过一番测试，我最终发现要完成这个操作必须具有`SeTcbPrivilege`权限，所以一个解决方案是从其他系统进程中“偷”一个令牌，这样就能获取权限了。然而修改已运行的程序的UIAccess是无效的，所以最后只能另起一个进程了。虽然这样有点瑕疵，但还是比之前的注入`explorer.exe`容错性要好、比数字签名更实际。

## 参考

[Window z-order in Windows 10 – ADeltaX Blog](https://blog.adeltax.com/window-z-order-in-windows-10/)，中文版：[Windows 10中的窗体Z序](https://blog.csdn.net/weixin_43820461/article/details/107610331)


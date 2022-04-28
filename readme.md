# 通过System令牌获取UIAccess

此项目用于获取UIAccess权限，它可以让你的程序窗口获得更高的Z序，比如高于任务管理器等。详情见[关于窗口Z序的介绍](https://blog.adeltax.com/window-z-order-in-windows-10/)，和它的[翻译版](https://blog.csdn.net/weixin_43820461/article/details/107610331)。

## 用法

程序最好设置请求管理员权限的清单，或者通过某个已提权的进程启动，否则获取不到UIAccess。加入头文件和源文件后，在程序的最开头加入`PrepareForUIAccess()`即可。返回值为错误代码。

## 流程

调用`PrepareForUIAccess`函数的程序获取UIAccess权限的步骤为：

* Step1    进程以管理员权限启动（进程A），它遍历进程列表，尝试获取具有SeTcbPrivilege权限的进程令牌，并用它启动另一进程B，此进程权限较高，可用于设置`TokenUIAccess`。
* Step2    A通过命名管道与B通信，传递一个普通的进程令牌并进入等待，B调用`SetTokenInformation`设置UIAccess标志，然后退出。
* Step3    A检查令牌是否已有UIAccess权限，如果是，用它启动进程C，此时C具有此权限，所以`PrepareForUIAccess`返回`ERROR_SUCCESS`；否则返回错误代码。

## 建议

使用这个权限的程序最好不要启动其他程序，包括`CreateProcess*`,`ShellExecute*`等等，因为新启动的程序默认会继承此UIAccess权限。

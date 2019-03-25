# Description

I successfully use 3 vulnerabilities in BSD to `root` the latest public macOS `10.13.6`.  

The 3 cases are:  
* (zdi-rcx15) necp arbitrary address write case. (link?)
* (zdi-rcx16) necp arbitrary address free case. (link?)
* (zdi-rcx17) progargsx heap leak case.  (link?)

Actually the last 2 cases are for root, the second case is not perfect, it needs the first case to make it work.

I use the same exploit technique from @ianbeer's async_wake_up. 
Please read the source code for reference.

# Notice
the 2 necp exploits will corrupt the underlying fg resources. So please avoid freeing the fg resource during process exit. One possible way to do this is to use the write primitive to modify the fg reference count.
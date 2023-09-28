1. Creator Process, Parent Process

일반적으로 Creator Process, Parent Process는 같다
그런데 다른 경우가 있는데, 예를 들어 UAC다.

다음은 UAC의 예시이다.

일반적으로 notepad를 실행시키면 다음과 같다.
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace/Process/normalnotepad.PNG)

그런데 notepad를 관리자 권한을 실행시키면 다음처럼 된다.
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace/Process/adminnoteapad.PNG)

Provider의 PID가 Creator Process이고 Properties의 ParentId가 Parent Process Id이다.
즉, 일반적으로 notepad.exe를 실행시키면 explorer.exe가 creator process이자 praent process가 된다.
하지만 UAC를 통해 실행시킬경우 


참고.
explorer.exe의 pid는 3680(0xE60)이고
svchost.exe의 pid는 12076(0x2F2C)이다.
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace/Process/explorerinfo.PNG)
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace/Process/svchost.PNG)


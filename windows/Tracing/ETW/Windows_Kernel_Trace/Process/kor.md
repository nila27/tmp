1. Creator Process, Parent Process

일반적으로 Creator Process, Parent Process는 같다
그런데 다른 경우가 있는데, 예를 들어 UAC다.

다음은 UAC의 예시이다.

일반적으로 notepad를 실행시키면 다음과 같다.
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace_Process/normalnotepad.PNG)

그런데 notepad를 관리자 권한을 실행시키면 다음처럼 된다.
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace_Process/adminnoteapad.PNG)

Provider의 PID가 Creator Process이고 Properties의 ParentId가 Parent Process Id이다.



참고.
explorer.exe의 pid는 3680(0xE60)이고
svchost.exe의 pid는 12076(0x2F2C)이다.
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace_Process/explorerinfo.PNG)
![Description of Image](/tmp/windows/Tracing/ETW/Windows_Kernel_Trace_Process/svchost.PNG)


![Description of Image](/tmp/test/뭣.webp)


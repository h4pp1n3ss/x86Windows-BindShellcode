# Windows/x86 - Bind TCP shellcode / Dynamic Null-Byte Free PEB & EDT method (419 bytes)
 
## Description: 

This a bind tcp shellcode that open a listen socket on port 1337. In order to accomplish this task the shellcode uses
the PEB method to locate the baseAddress of the required module and the Export Directory Table to locate symbols. 
Also the shellcode uses a hash function to gather dynamically the required symbols without worry about the length. 


- Author: h4pp1n3ss
- Date: Mon 10/05/2021
- Tested on: Microsoft Windows [Version 10.0.19042.1237]

# Windows API 

This shellcode uses a couple of Windows API from ws2_32.dll

### WSAStartup function (winsock2.h)

[WSAStartup function](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup)
```c
int WSAStartup(
  WORD      wVersionRequired,
  LPWSADATA lpWSAData
);
```

and 

### WSASocketA function (winsock2.h)

[WSASocketA function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa)

```c
SOCKET WSAAPI WSASocketA(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOA lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
);
```

### bind function (winsock2.h)

[bind function](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind)

```c
int bind(
  SOCKET         s,
  const sockaddr *addr,
  int            namelen
);
```


### listen function (winsock2.h)

[listen function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen)

```c
int bind(
  SOCKET         s,
  const sockaddr *addr,
  int            namelen
);
```


### WSAGetLastError function (winsock.h)

[WSAGetLastError function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen)

```c
int WSAGetLastError();
```


### accept function (winsock2.h)

[WSAGetLastError function](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept)

```c
SOCKET WSAAPI accept(
  SOCKET   s,
  sockaddr *addr,
  int      *addrlen
);
```



# Resources

- [Corelan - Exploit writing tutorial part 9](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)
- [Shell-storm](http://shell-storm.org/shellcode/)
- [Phrack - History and Advances in Windows Shellcode](http://www.phrack.org/issues/62/7.html#article)
- [Skape - Understanding Windows Shellcode ](http://www.hick.org/code/skape/papers/win32-shellcode.pdf)







---
title: Windows API Programming with Python
---

**Description: Programming with the Windows API in Python, utilizing the ctypes library**

**NOTE: When you're interacting with the WinAPI, you'll notice that some functions end in a W (EX: CreateFileW) while there are also the equivalent which end in an A (EX:CreateFileA). The difference is that functions ending in an A are ANSI functions while those that end in W are Unicode functions. In my experience, Python works best with the Unicode (W) functions. If you attempt to use ANSI functions, you may encounter problems.  When I tried to use the ANSI function CreateFileW, I found that it wasn't creating the full file name I was specifying, but rather only creating a file with only the first letter I was specifying.**

# Getting Started

We can interact with the [Windows API](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) using Python by simply importing the [ctypes](https://docs.python.org/3/library/ctypes.html) library! 

The `ctypes` library gives us access to C-compatible data types and lets us call functions in *Dynamic Link LIbraries (DLLs)* which is what Windows uses for its WinAPI functions. So we can import DLLs and then call the functions that those DLLs provide us access to!

We know what DLL that we need to import to use a specific WinAPI function by looking through the Windows documentation.

## Popping a Message Box

For example, let's say that we want to display a [message box](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox). Reading through the documentation, we see that the required DLL is `User32.dll`:

![](https://i.imgur.com/FdeDiuz.png)

The C++ syntax to use the `MessageBoxW` function is:

```c++
int MessageBox(
  [in, optional] HWND    hWnd,
  [in, optional] LPCTSTR lpText,
  [in, optional] LPCTSTR lpCaption,
  [in]           UINT    uType
);
```

We have to supply:

* a `handle` to the owner window of the message box. But this parameter is optional if we don't want the message box to have an owner window. We can set this to *null*, or in Python, `None`
* An `lpText` string value which is the message to be displayed in the message box
* An `lpCaption` string value which is going to be used as the title to the message box. We can also set this one to *null* & it'll default to being **Error**
* A `utype` value which defines the contents and how the message box behaves. We set this using a hexadecimal value listed in the [documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox) according to what we want the message box to do.
	* So if we want the end user to just be able to click OK, then we'd set it to `MB_OK` & supply the `0x00000000` value as the argument to the `MessageBox` function (We drop the appended *L* when using `utypes` in Python) 

Our code would look like this:

```python3
import ctypes

dllHandle = ctypes.WinDLL("User32.dll")
dllHandle.MessageBoxW(None, "This is a message box", "This is a title", 0x00000000)
```

And when we run it:

![](https://i.imgur.com/Ez506NW.png)

You may have also noticed that according to the documentation page for the `MessageBoxW` function, we can also display icons in the message box as well! We can do so by simply putting the hex value within the `uType` argument which is the last argument we supply to the function.

So if we wanted to show an informational message box for example, we'd use the `MB_ICONINFORMATION` icon which has a corresponding hex value of `0x00000040L`. So our code would be:

```python3
import ctypes

dllHandle = ctypes.WinDLL("User32.DLL")
dllHandle.MessageBoxW(None, "Here is some useful information!", "Box full of useful information", 0x00000040)
```

![](https://i.imgur.com/x5M6JUd.png)
## Getting Current Working Directory

Let's say we wanted to get the directory that we're currently in using the WinAPI. The documentation for this API function is [here](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory). 

According to the documentation, we see that we need to import the `Kernel32.dll` library:

```python3
import ctypes

dllHandle = ctypes.WinDLL("Kernel32.dll")
```

And according to the documentation, the function requires 2 arguments:

1. The length of the *buffer* we allocate to receive the output data when the function is ran
2. The actual *buffer*

So now we know that we must create a buffer and get the length of it.

Well the `ctypes` library has a function `create_unicode_buffer` that we can utilize to create a unicode buffer 
and according to their [documentation](https://docs.python.org/3/library/ctypes.html), we can get the length of the buffer by using the `sizeof` function:

![](https://i.imgur.com/maX10cK.png)

Let's write this code!

```python3
import ctypes

dllHandle = ctypes.WinDLL("Kernel32.dll")

buffer = ctypes.create_unicode_buffer(1024)
dllHandle.GetCurrentDirectoryW(ctypes.sizeof(buffer), buffer)
print(buffer)
```

Running this code:

![](https://i.imgur.com/65H9pF4.png)

This doesn't exactly give us the value that's inside of the buffer, but rather it prints the *buffer object*. Looking at the `ctypes` documentation, we can access the value contained within Windows type variables by simply using the `value` attribute. This example was taken from the `ctypes` documentation page:

![](https://i.imgur.com/0P9phUi.png)

From the above image, first we create an `c_int` data type with the value `42` contained within it. When we print the variable, it doesn't just give us the value. In order to exclusively access the `42` value, we must call the `value` attribute of that variable.

Let's try using the `value` attribute of the `buffer` variable we created:

```
import ctypes

dllHandle = ctypes.WinDLL("Kernel32.dll")

buffer = ctypes.create_unicode_buffer(1024)
dllHandle.GetCurrentDirectoryW(ctypes.sizeof(buffer), buffer)
print(buffer.value) 

### The only difference in the code is we added .value to the buffer variable when printing it ###
```

![](https://i.imgur.com/GFftrC4.png)

And as you can see, it worked! We're able to print out the specific directory that we're located in!


## Playing Windows Beeps

We can even be annoying with how we interact with the Windows API! We can play beeps by using the [MessageBeep function](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebeep)!

The syntax for this function in C++ is:

```c++
BOOL MessageBeep(
  [in] UINT uType
);
```

So we only have to supply the `uType` which defines what beep type that we want to play. A simple beep would be `0xFFFFFFFF` while a critical beep would be:  `0x00000010`

According to the documentation we need to use the `User32.dll` so our code to play a critical beep would look like:

```python3
import ctypes

dllHandle = ctypes.WinDLL("User32.dll")
dllHandle.MessageBeep(0x00000010)
```

Have fun with this one!

## Creating & Writing To A File

According to the Windows documentation, if we want to create a file, we'd use the `CreateFileW` function which requires `Kernel32.dll`. 

The syntax for this function is:

```c++
HANDLE CreateFileW(
  [in]           LPCSTR                lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);

```

The arguments we need to supply include:

* `lpFileName` - a string that represents the filename that we want to create
* `dwDesiredAccess` - the requested access to the file. We must use the hex value equivalent to the name of the access we want to grant to the file:

| Symbolic Name | Hex Value | Description |
| ------------------ | ------------- | ------------- |
| GENERIC_READ | 0x80000000 | Allow read access to file |
| GENERIC_WRITE | 0x40000000 | Allows write access to file |
| GENERIC_EXECUTE | 0x20000000 | Allows application to execute file |
| DELETE | 0x10000000 | Allows application to delete file |
| FILE_READ_ATTRIBUTES | 0x0080 | Allows application to read the file's attributes |
| FILE_WRITE_ATTRIBUTES | 0x00100 | Allows application to write the file's attributes |
* `dwShareMode` - the requested share mode of the file. If we set it to `0`, then once the file is created, it can't be opened again until the handle to the file is closed
* `lpSecurityAttributes` - a pointer to a `SECURITY_ATTRIBUTES` structure that details the security attributes of the file you want to create
* `dwCreationDisposition` - the action to take on a file that exists or does not exist. We must again use the hex equivalent to the action name that we want to take on the file:

| Value | Meaning | 
| ------ | ---------- |
| CREATE_ALWAYS (2) | Creates a file always. If the specified file already exists & is writable, we overwrite it |
| CREATE_NEW (1) | Creates a new file only if one doesn't already exist. If the specified file already exists, the function fails & the error code is set to `ERROR_FILE_EXISTS`. If the specified file doesn't already exist & is a valid, writable path, then a new file is created |
| OPEN_ALWAYS (4) | Always opens a file. If the specified file exists, the function succeeds and the error is set to `ERROR_ALREADY_EXISTS`. If the specified file doesn't exist & is a valid, writable path, then the file is created |
| OPEN_EXISTING (3) | Opens a file only if it exists. If the specified file doesn't exist, the function fails & the error is set to `ERROR_FILE_NOT_FOUND` |
| TRUNCATE_EXISTING (5) | Opens a file & truncates it so the size is zero bytes, only if the file exists. If the specified file doesn't exist, the function fails & the error code is set to `ERROR_FILE_NOT_FOUND`. The calling process must open the file with the `GENERIC_WRITE` bit set as the `dwDesiredAccess` parameter |


* `dwFlagsAndAttributes` - the file attributes & flags
* `hTemplateFile` - optional & can be NULL or in our case, `None`, a handle to a template file with `GENERIC_READ` access rights. Template file supplies file attributes & extended attributes for the file being created.

Our code would look like this:

```python3
import ctypes

dllHandle = ctypes.WinDLL("Kernel32.dll")
fileHandle = dllHandle.CreateFileW("testfile.txt", 0x40000000, 0, None, 1, 0, None)

dllHandle.CloseHandle(fileHandle) # Close file handle after creating new file
```

And running this code:

![](https://i.imgur.com/EqUu3Jt.png)

We see that an empty file named `testfile.txt` is created!

Now what if we wanted to write data to that file? We could use the [WriteFile WinAPI function](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) which requires the following syntax:

```C++
BOOL WriteFile(
  [in]                HANDLE       hFile,
  [in]                LPCVOID      lpBuffer,
  [in]                DWORD        nNumberOfBytesToWrite,
  [out, optional]     LPDWORD      lpNumberOfBytesWritten,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

* `hFile` is a handle to the file that we just created. This is returned by the `CreateFileW` & `openFile` functions
* `lpBuffer` is a pointer to a buffer containing the data that you want to write to the file
	* We can create a buffer by using the `create_string_buffer` function from the `ctypes` library
* `nNumberOfBytesToWrite` is the number of bytes that we want to write to the file. We can simply use the `sizeof` function of the buffer we have created
* `lpNumberOfBytesWritten` is optional and its a pointer to a variable that receives the number of bytes written
	* This variable is a `LPDWORD` type & we can create this variable type via `ctypes.POINTER(ctypes.c_ulong)()` 
* `lpOverlapped` is a pointer to an `overlapped` structure

Our code would look like this:

```python3
### Code from previous function
import ctypes

dllHandle = ctypes.WinDLL("Kernel32.dll")
fileHandle = dllHandle.CreateFileW("testfile.txt", 0x40000000, 0, None, 1, 0, None)


buffer = ctypes.create_string_buffer(b'This is a file')
bytesWritten = ctypes.POINTER(ctypes.c_ulong)()

dllHandle.WriteFile(fileHandle, buffer.value, ctypes.sizeof(buffer), bytesWritten, None)

dllHandle.CloseHandle(fileHandle) # Close file handle after creating new file
```

And running this code:

![](https://i.imgur.com/8kPngOP.png)

We see that we have now created a file that is not empty! Outputting the contents of the file:

![](https://i.imgur.com/Ccn5NLp.png)

We've successfully written data to a file!
## Deleting A File

Let's say that we don't like that file that we've recently created and now we want to delete it, we can do so by using the [DeleteFileW WinAPI function](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew)!

The syntax for this function is:

```C++
BOOL DeleteFileW(
  [in] LPCSTR lpFileName
);
```

* `lpFileName` is a string that's the file path that we want to delete

And we can still use the `Kernel32.dll`!

Our code would look like:

```python3
import ctypes

dllHandle = ctypes.WinDLL("Kernel32.dll")
dllHandle.DeleteFileW("testfile.txt")
```

And running the code:

![](https://i.imgur.com/aNWOdrT.png)

We deleted the file!

## Making HTTP Requests


# Resources
* https://www.youtube.com/watch?v=0Y6YoETR_GU
* https://github.com/wilsonator/TCMWindowsAPIs
* https://docs.python.org/3/library/ctypes.html

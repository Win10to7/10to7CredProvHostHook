# CredProvHostHook

> [!CAUTION]
> **This repository contains a version of CredProvHostHook from that may 2025 and it is considered unfinished and is not usable in its current state. This repo was made to archive the project's code, use at your own risk.**

> [!CAUTION]
> **CredProvHostHook was only tested on Windows 10 version 21H2 (VB) and might not work on anything else.**

> [!WARNING]
> **THIS PROJECT IS IN EARLY DEVELOPMENT AND MIGHT BE UNSTABLE. Use at your own risk. We are not liable for any damages that may or may not occur.**
>
> **PLEASE DISABLE BITLOCKER BEFORE USING THIS**
> 
> **PLEASE HAVE A USB DRIVE WITH A WINDOWS INSTALLER READY BEFORE HAND TO BE ABLE TO RECOVER YOUR WINDOWS INSTALL IN THE EVENT OF CREDPROVHOSTHOOK BRICKING YOUR SYSTEM**

In order to install CredProvHostHook, you need to write to protected registry keys which you ordinarily do not have permission to write to. An easy way to do this is to [download RunTI](https://github.com/aubymori/RunTI) and use it to run a Command Prompt (`cmd.exe`) window as the special internal TrustedInstaller user account. The only key which you must write to is:

- `HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{7a872d34-bc6b-4f83-b199-22e9c0a91ddc}\InProcServer32`
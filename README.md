# go-judge-win-test

Test code that might used in [go-judge](https://github.com/criyle/go-judge)/executorserver in the future as a support for windows platform.

## Current Design

- [x] Create [Job Object](https://docs.microsoft.com/en-ca/windows/win32/procthread/job-objects) and apply cpu & memory & active process limitation
- [x] Create IOCP Message Queue
- [x] Create Pipe for Stdin, Stdout, Stderr
- [x] Create Process (As User)
- [x] Create Desktop
- [x] Wait On Exit Message
- [ ] Create restricted user environment
- [ ] Get Running Result From [JOBOBJECT_EXTENDED_LIMIT_INFORMATION](https://docs.microsoft.com/en-ca/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)

## Security

- [ ] Job Object can be escaped from through Win32_Process.Create
- [ ] File system is not isolated
- [ ] Process list table is not isolated

## Ideas

- [ ] Windows container by [HCS](https://github.com/microsoft/hcsshim)
- [ ] Run on [windows sandbox](https://techcommunity.microsoft.com/t5/windows-kernel-internals/windows-sandbox/ba-p/301849)
- [ ] Run on [docker for windows](https://docs.microsoft.com/en-us/virtualization/windowscontainers/about/) [Talk on YouTube](https://www.youtube.com/watch?v=85nCF5S8Qok)

## Reference

- Win API: [golang.org/x/sys/windows](https://godoc.org/golang.org/x/sys/windows)
- Win API that are missing: [contester/runlib](https://github.com/contester/runlib)
- [CreateProcessAsUserW](https://docs.microsoft.com/en-ca/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [iceb0y/windows-container](https://github.com/iceb0y/windows-container) / core
- [kernelbin/BOIT](https://github.com/kernelbin/BOIT) / BOIT Server / Simple sandbox
- [Chromium Sandbox](https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox.md)

## Windows Access Control Model

- [Security Model](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-components)

### Access Token

- [Access Token](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Security Identifier (SID) for user / groups / logon session / owner / primary group
- Privilleges
- Default DACL
- Source of the access token
- Primary / impersonation token
- Restricting SIDs
- Current impersonation levels

### Security Descriptor

For a securable object. Contains

- Discretionary Access Contol List (DACL)
- System Access Control List (SACL)

ACL contains list of Access Control Entries (ACE) with access rights and trustee.

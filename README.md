# detect-filename-block

## DESCRIPTION
  - minifilter driver example to monitor pre-determined directory in root volume (volume where OS boot),
  - detect if filename transfer to that directory contains pre determined text
  - block the transaction, if both terms are met

## HOW TO INSTALL
### using inf
locate the inf file included in specific release for your OS version. right click and choose install

### using pnputil + inf
run this in commandline 
```c
pnputil /add-driver <inf-path> /install
```
      
## HOW TO START & STOP 
### start
run this in command line
```c
sc start detect-filename-block
```
      
### stop
run this in command line
```c
sc stop detect-filename-block
```
      
## HOW TO MONITOR LOG

   use DebugView (https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)

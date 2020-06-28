# detect-filename-block

DESCRIPTION
  - minifilter driver example to monitor pre-determined directory in root volume (volume where OS boot),
  - detect if filename transfer to that directory contains pre determined text
  - block the transaction, if both 

HOW TO INSTALL
  a. using inf
    - locate the inf file included in specific release for your OS version. right click and choose install
  b. using pnputil + inf
    - run this in commandline 
      pnputil /add-driver <inf-path> /install
      
HOW TO START & STOP 
  start
    - run this in command line
      sc start detect-filename-block
      
  stop
    - run this in command line
      sc stop detect-filename-block
      
HOW TO MONITOR LOG
  use DebugView (https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)

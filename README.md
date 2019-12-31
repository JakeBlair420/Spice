# Spice

## Basic overview
This was written by the @JakeBlair420 team (@s1guza, @stek29, @sparkey, @littlelailo)
There is a presentation from @littlelailo he gave at 36C3 that gives a pretty good overview over the whole jailbreak including the bugs that were used and how we exploited them.
So please watch this first before looking at the code base to get a good overview.
The bugs can be used to exploit this on all versions of iOS 11, in theory it's also possible to pop the i5 on some versions of iOS 10 with this, but the repo and spice only support 64 bit devices.
The jailbreak is in an incomplete state atm and only works on none SMAP devices (A7-A9) and with hardcoded symbols (but the offsetfinders are also nearly done).
We added comments as much as possible to explain what still doesn't work/needs more testing if someone wants to port this to other devices.

## Bugs

### Racoon write what where bug

### ASLR bypass

### kASLR leak

### lightspeed (main kernel bug to get kernel read/write)

### RootDomainUserClient memory leak we use for spraying

### kASLR weakness

## Repo

## Usage

## Installation
For the installation copy stage 2 onto the device into some random folder and stage 3 (/usr/lib/racoon.dylib) and 4 (/mystuff/stage4) at their right paths.
Then execute racoon till it doesn't kernel panic anymore to make sure you got the right offsets.
Then also set the nvram variable boot-args to "this boy needs some milk" and check if the system keeps running stable even with racoon (this is the killswitch).
If you did you can then go for the real untether by replacing one of the launch daemons and unsetting the variable to run the untether on the next boot.
There you need to watch out for three things:
- the launch daemon isn't used by anything important (namely springboard) (otherwise you will softbrick when it fails to run)
- the launch daemon doesn't have keepalive set (if it does launchd will try to always restart it if you crash it and that will also softbrick)
- the launch daemon starts up early
We found out that you can safely replace prdaily but this one will start really late during boot so you get the same behaviour we also showed in febuary in the demo.
You can also replace wifiFirmwareLoaderLegacy, but this one has keepalive set so you might softbrick. The big advantage you get tho is speed because it starts really early.
After you chose your daemon you need to update jailbreak.m to unload the right one (currently unloads prdaily) and recompile stage 4/replace it on disk again.
As a last step please run sync a few times to make sure that everything got written to disk and then fingers crossed it works and you don't softbrick.
If you restart and it keeps kernel panicing boot into recovery and set the boot-args to "this boy needs some milk" using irecovery and then reboot this will disable stage 2/the kernel exploit.
If you still can't boot after that you basically softbricked sry.

## References
- writeup on this one kernel bug
- writeup on lightspeed
- presentation from panicall
- presentation from pod2g
- acron

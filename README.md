# cmtscrack
Bit of parallelized C code to crack the CMTS MIC from a DOCSIS modem configuration. Requires a config.cm and a wordlist. It's all a bit rough but it gets the job done. 

## usage
```
$ cmtscrack ./config.cm ./wordlist
```

## notes
* The number of threads to run is currently defined as a global variable, so tweak that to suit.
* Based off original code dug up on codeplex somewhere. Issues with mutex locking killing performance on higher thread counts lead to this version.

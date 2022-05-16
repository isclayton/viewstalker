# Viewstalker
A tool for identifying and exploiting vulnerable Viewstate implementations in ASP.NET 


```
usage: ViewStalker [-h|--help] [-l|--hosts <file>] [-a|--address "<value>"]

                   A tool for identifying vulnerable ASP.NET viewstates

Arguments:

  -h  --help     Print help information
  -l  --hosts    Path to file with list of hosts to check, one per line
  -a  --address  Single host to check
```



### TODO:
- [x] initial target handling and parsing
- [ ] recreate blacklist3r functionality for bruting keys
- [ ] automatic payload generation and exploitation
- [ ] Support for JSF viewstates

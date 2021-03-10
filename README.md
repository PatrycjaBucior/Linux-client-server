# Linux-client-server
This is a linux client-server program showing example of poll usage.
Producent program is able to serve many clients (konsument program) at the same time.


To compile programs use:
```
gcc producent.c -o producent
gcc konsument.c -o konsument

```

```
producent -p <float> [<addr>:]port
	
    Usage:
    	-p <float>     - producing data speed (unit: <float> * 2662[B/s])
        [<addr>:]port  - server localization. Suggested:  "8000"
    
    examples: 	./producent -p 1 localhost:8000
                ./producent -p 0.5 8000
                ./producent -p 2 8000
                
konsument -c <int> -p <float> [<addr>:]port

    Usage:
	-c <int>      - capacity of client warehouse counted in blocks of size 30KiB
	-p <float>    - data consumption speed (unit: <float> * 4435[B/s])
    	-d <float>    - degradation speed (unit: <float> * 819[B/s])
	[<addr>:]port - address of server (producer). Have to be same as server ex.: ":8000".
        
    examples:	./konsument -c 1 -p 10 -d 0.5 8000
                ./konsument -c 2 -p 1 -d 0 localhost:8000
                ./konsument -c 1 -p 5 -d 0.5 8000

Note: Start server first, and then connect any number of clients.

```

#Mediastorage-proxy configuration 

* [TheVoid settings](#TheVoid-settings)
* [Mediastorage-proxy settings](#Mediastorage-proxy-settings)
* [Startup order of the proxy](#Startup-order-of-the-proxy)

Proxy provides HTTP API to the client with the help TheVoid. Access to Elliptics provided by using libmastermind and client interface of Elliptics. Configuring proxy is logically divided to set TheVoid parametrs and other configuration parametrs. The configuration file has JSON format. The overall structure of the configuration file is as follows:
```
{
"thevoid":{},
"application":{}
}
```
Where are:
* `thevoid` section - TheVoid settings;
* `application` section - other configuration parametrs.

The scheme of work Mediastorage-proxy with the client.

![scheme of work](work_scheme3.png)

##TheVoid settings
```json
        "endpoints": [
                "unix:/tmp/thevoid/mediastorage-proxy.sock",
                "0.0.0.0:8082"
        ],
        "backlog": 128,
        "safe_mode": true,
        "threads": 2,
        "buffer_size": 65536,
        "daemon": {
                "monitor-port": 20001
        },
```
| Parameter | Description |
|-----------|-------------|
| `endpoints` | The sockets that proxy listens. Unix and tcp sockets can be used. |
| `backlog` | Size of queue for each socket. |
| `safe_mode` | Proxy with this option catches all uncaught errors and return 500 code of error, if the value this parameter is TRUE. |
| `threads` | Number of threads to handle connection. |
| `buffer_size` | Buffer size of packages. |
| `monitor-port` | Port value for monitoring proxy. |
##Mediastorage-proxy settings
```json
		"application" : {
                "elliptics-log" : { 
                        "path" : "/tmp/log/mediastorage/elliptics.log", 
                        "level" : 2
                },
                "proxy-log" : {   
                        "path" : "/tmp/log/mediastorage/proxy.log", 
                        "level" : 2 
                },
                "mastermind-log" : { 
                        "path" : "/tmp/log/mediastorage/mastermind.log", 
                        "level" : 2 
                },
                "timeouts" : {  
                        "wait" : 30, 
                        "check" : 60 
                },
                "cfg-flags" : 4, 
                "elliptics-threads" : {  
                        "io-thread-num" : 16, 
                        "net-thread-num" : 4  
                },
                "mastermind" : { 
                        "nodes" : [    
                                {
                                        "host" : "host.example.com",   
                                        "port" : 10053  
                                }
                        ],
                        "group-info-update-period" : 10  
                },
                "die-limit" : 1, 
                "eblob-style-path" : true,
                "base-port" : 1024,
                "chunk-size" : { 
                        "write" : 10, 
                        "read" : 10
                }
        }
```
| Parameter | Description |
|---------------|-------------|
| `elliptics-log`, `proxy-log`, `mastermind-log` | There are Elliptics client, proxy and *libmastermind* logs. Should be set the path to the log-file and the log level (value can be from 0 to 5). |
| `timeouts`| The timeouts settings.  Allow you to override at runtime the previous values for timeouts.</br> *`wait`* - a time to wait for the operation complete,</br>  *`check`*- sets the wait for a response from the host. If it stops responding then rebuild the routing table. </br>|
| `cfg-flags` | Configuration flags of the Elliptics client. |
| `elliptics-threads` | Configuration of the Elliptics client threads. The following parameters are used to configure the client - *`io-thread-num`* -  a number of IO threads in processing pool,  *`net-thread-num`* - a number of threads in network processing pool. |
| `mastermind` | Configuration for the *libmastermind*. Allows to communicate the mediastorage-proxy with Mastermind in Cocaine. Mastermind calculates the load on the nodes.  It lets say what the nodes are most loaded and where should be the load on nodes for write operations. To configure the client are using the following parameters - *`nodes`* - paths to all the Cocaine locators that can go to Mastermind (values for a path to the cocaine-runtime and for a port where is the locator), *`group-info-update-period`* - a time after which should be updated the information (this parameter in seconds). |
| `die-limit` | Sets how many live connections between Mediastorage-proxy and Elliptics that to assume that the system is operable. But it is impossible make a record if the the system contains fewer connections because it works in read-only mode. |
| `eblob-style-path` | Allows set to use style of path like eblob. If the value is `TRUE` that's eblob, else - filesystem. |
| `base-port` | The value for Dnet base port. |
| `chunk-size` | A size of a single piece of data to be written or to be read. The size is specified in MB. It is a required parameter. |

##Startup order of the proxy
Mediastorage-proxy runs as follows:

1. starts proxy,
2. proxy loads *libmastermind*,
3. *libmastermind* loads cache,
4. *libmastermind* connects to Mastermind,
5. gets namespace setting from Mastermind and sends it to proxy,
6. proxy is ready to work.


The scheme of work at upload operation.

1. The client transmits to proxy the following parameters - key, value and namespace.
2. Proxy transmits to *libmastermind* namespace, size.
3. *Libmastermind* transmits to proxy a couple id.
4. Proxy upload the data to Elliptics in accord a couple id.
5. Proxy send to client a couple id (if operation was successful) or an error message (if operation was successful and delete data in those groups, in which all the same managed to upload). 

The scheme of work at read/delete a data operations.

1. The client transmits to proxy the following parameters - key name, namespace and couple with the number of group.
2. Proxy transmits to *libmastermind* a couple id with the number of group.
3. *Libmastermind* transmits to proxy a couple id.
4. Proxy delete or read the data to Elliptics in accord a couple id.
5. Proxy send to client a data in read operation or a message on the status of delete operation.

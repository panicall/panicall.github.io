---
layout: default
author: juwei lin
date: 2018-10-09 15:16:00 +0800
---

# Use PanicXNU to fuzz IOKIT

Basic Process
* Add code coverage support for IOKit modules
* Add passive fuzzing 
* Deliver PanicXNU

## Add Code Coverage Support for IOKit Modules
* Module SBI 
* Update Trace Client
* Install New IOKit Module and Trace Client

### Module SBI
You can download SBI [here](https://adc.github.trendmicro.com/CoreTech-MARS/MachoSBI)  

1. execute IDAParser.py to extract information from macho (make sure your macholib version is above 1.8.0)
   `python BinAnalyzer/IDAParser.py ~/Desktop/IOBluetoothFamily`
2. execute MachoGen.py to generate new macho  
   `python Generator/MachoGen.py ~/Desktop/IOBluetoothFamily`
3. chmod 
   `chmod 755 ~/Desktop/IOBluetoothFamily`  

### Update Trace Client
TraceClient is inside SBI.  
If target IOKit module(e.g. IOBluetoothFamily) is not in `trace_coverage.cpp\iokit_module_list`, add it:
```C
char iokit_module_list[][100] = {
    "com.apple.iokit.IOGraphicsFamily",
    "com.apple.driver.AppleHDA",
    "com.apple.iokit.IOHDAFamily",
    "com.apple.driver.AppleHDAController",
    "com.apple.driver.DspFuncLib",
    "com.apple.iokit.IOBluetoothFamily"
};
```
Then re-compile the trace module.

### Install New IOKit Module and Trace Client
1. install new IOKit module(e.g. IOBluetoothFamily)
   * turn off sip
      `sudo nvram boot-args="debug=0x146 kext-dev-mode=1 kcsuffix=release keepsyms=1"`
      `reboot`
   * replace original module with the new one
   * chown  
     `chown -R root:wheel /System/Library/Extension/IOBluetoothFamily.kext`
   * install  
     `sudo kextcache -i /`
2. install trace client
   * chown  
    `chown -R root:wheel trace_module.kext`
   * install  
    `sudo kextload trace_module.kext`
   * set autorun
      copy `com.panicall.trace_module.plist` to `/Library/LaunchDaemons/`
   * reboot


## Add Passive Fuzzing
* Setup Mysql & MongoDB
* Install Passive Hook Client and Server
  
Download XNUPassive [here](https://adc.github.trendmicro.com/CoreTech-MARS/XNUPassive)  

### Setup Mysql & MongoDB  
1. Mysql
   * use mysql 5.7.20
   * create db 'Panicall' with username 'root' and password 'root'：` mysqladmin  -u root -p  create Panicall`
   * create tables by executing [MacFuzzServer/mysql/Schema.sql](https://adc.github.trendmicro.com/CoreTech-MARS/XNUPassive/blob/master/MacFuzzServer/mysql/Schema.sql)
   * allow anyone to connect  
      `GRANT ALL PRIVILEGES ON *.* TO 'myuser'@'%' IDENTIFIED BY 'mypassword' WITH GRANT OPTION;`
      `flush privileges`
   * golang install mysql  
      `$ go get -u github.com/go-sql-driver/mysql`  

2. MongoDB
   * brew install mongodb
   * create db dir 
   * run mongo:  mongod --dbpath db_dir --bind_ip 0.0.0.0
   * connect to mongo: mongo --host 127.0.0.1:27017
   * create db(MacFuzz) and collections(IOKit, XNU)
     * use MacFuzz
     * db.IOKit.insert({"test":"test"})
     * db.XNU.insert({"test":"test"})  
     * db.PanicLogs.insert({"signature":"test", "filename":"test"})  


### Migrate Mysql & MongoDB  
1. Mysql  
   * list the db we want to migrate  
    ```
    mysql -u root -p
    show databases;
    ```

   * export db  
    ```
    mysqldump -u root -o Panicall > Panicall.sql 
    ```
   * import db  
    ```
    mysqladmin  -u root -p  create Panicall  
    mysql -u root -p Panicall < Panicall.sql
    ```
2. MongoDB  
   * list the db and collections we want to migrate  
    ```
    \> show dbs
    Coverage  0.001GB
    Last_Report     0.000GB
    MacFuzz         0.003GB
  
    \> use Coverage
    switched to db Coverage
    \> show collections
    IOKitCov
    SyscallCov
  
    \> use Last_Report
    switched to db Last_Report
    \> show collections
    Report
  
    \> use MacFuzz
    switched to db MacFuzz
    \> show collections
    IOKit
    PanicLogs
    XNU
    ```
   * export the data  
    >./mongoexport -d DataBaseName -c CollectionName -o XXX.dat  
    ```
    mongoexport -d Coverage -c IOKitCov -o IOKitCov.dat
    mongoexport -d Coverage -c SyscallCov -o SyscallCov.dat

    mongoexport -d Last_Report -c Report -o Report.dat

    mongoexport -d MacFuzz -c IOKit -o IOKit.dat
    mongoexport -d MacFuzz -c PanicLogs -o PanicLogs.dat
    mongoexport -d MacFuzz -c XNU -o XNU.dat

    ```
   * import the data  
    >./mongoimport -h 127.0.0.1:port -u xxx -p xxx-d DataBaseName -c CollectionName XXX.dat
    ```
    mongoimport -d Coverage -c IOKitCov IOKitCov.dat  
    mongoimport -d Coverage -c SyscallCov SyscallCov.dat  

    mongoimport -d Last_Report -c Report Report.dat

    mongoimport -d MacFuzz -c IOKit IOKit.dat
    mongoimport -d MacFuzz -c PanicLogs PanicLogs.dat
    mongoimport -d MacFuzz -c XNU XNU.dat
    ```
   
### Install Passive Hook Client and Server
1. Install Passive Client  
   * load MacFuzzExtension.kext and set autorun  
    copy `com.panicall.MacFuzzExtension.plist` to `/Library/LaunchDaemons/` 
   
2. Install Passive Server  
`python feedback.py`  

## Deliver PanicXNU
### Compile PanicXNU for IOKit
`make HOSTOS=darwin HOSTARCH=amd64 TARGETMOD=iokit`  

### Run PanicXNU against VM Machines  
`syz-manager -config=/Users/juwei_lin/go/src/github.com/Panicall/PanicXNU/config/iokit_fusion.cfg -v=5 -debug=false`

### Run PanicXNU against Physical Machines
`syz-manager -config=/Users/juwei_lin/go/src/github.com/Panicall/PanicXNU/config/iokit_physical.cfg -v=5 -debug=false`  

  [Back Home]({{site.url}}{{site.baseurl}})

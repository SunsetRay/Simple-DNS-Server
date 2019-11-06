# Simple-DNS-Server-with-learning
A Simple DNS Server with learning. Implemented DNS protocol.

Following these steps to initiate:
1. Configure database. Import ./dns.sql to your MySQL database. Some commonly used websites are included.

2. Add your local DNS server in config.txt after "default_dns=". If you don't know your local DNS server, you can use "ipconfig /all" command to find it out.

3. Configure Python environment. Supported Python 3.5+. 

4. Change WLAN 2 to your own network name in dns_config.bat, and run this script.

5. Input "python main.py" in your console. To show other supported arguments, run the code using "python main.py -h".

-d: Simple debug output, -dd: Complex debug output. These two args are mutually exclusive.
-s [local DNS server address]: Use this local DNS server.
-f [config file path]: Use a certain config file, which include whether to learn and default local DNS server address.

6. Change WLAN 2 to your own network name in dns_deconfig.bat, and run this script to finish the experiments.

Please note:
./dns_config.bat and ./dns_deconfig.bat are only supported in Windows. Please configure by yourself if you are using other OS. 
Contact：discat@foxmail.com

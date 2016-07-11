README

EgaReEncryptionService.jar 

EGA ReEncryption server: servers re-encrypted data streams from the archive.

Startup: 

	java -jar EgaReEncryptionService.jar [-l, -f, -p, -t]

"java -jar EgaEgaReEncryptionService.jar" starts the service using default configuration (Port 9124). 
	Parameter '-l' allows to specify a different path to the database config XML file
	Parameter '-f' allows to specify a different name of the database config XML file
	Parameter '-p' allows to specify a different port for the service to listen
	Parameter '-t' performs a self-test of the service

Startup as service:

	nohup java -jar EgaEgaReEncryptionService.jar > res.log 2>&1&

Defaults - Port: 9124, Config File: 'DatabaseEcosystem.xml', Config Path: './../headers/'

The service creates a new directory "dailylog". In this directory there is a log file that lists all requests sent to this service. A new log file is created at the beginning of each new day.

In the future this service will also support direct REST queries against the log tables. Not yet, however.

------------

Project is created using Netbeans.

Netbans uses ant, so it can be built using ant (version 1.8+). Ant target "package-for-store" creates the packaged Jar file containing all libraries. There are no further dependencies, everything is packaged in the Jar file.

Servers use Netty as framework. Client REST calls use Resty.

------------

The service runs HTTP only. It is intended that way.

------------

API
 Base URL: /ega/rest/reencryption/v1

 POST /ega/rest/reencryption/v1/files/ {"downloadrequest": user, file id, file path, reencryption key, format} 
 /ega/rest/reencryption/v1/downloads/{ticket}?ip={ip} -- download a ticket (returns binry stream)
 /results/{ticket}?ip={ip} -- gets the MD5 and size of the data sent, after download
 /ega/rest/reencryption/v1/stats/load                   returns server CPU load
 /ega/rest/reencryption/v1/stats/hits[?minutes=minutes] returns # of hits (approximate) within the past {minutes} minutes
 /ega/rest/reencryption/v1/stats/avg[?minutes=minutes]  returns response time/avg of hits (approximate) within the past {minutes} minutes




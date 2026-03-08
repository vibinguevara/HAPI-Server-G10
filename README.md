## Pre-Requisites
1. Java 17 - Maven Built
2. PostgreSQL DB - Version 14
3. Python - 3.x + version (latest is best)

## DB Details
```
url: jdbc:postgresql://localhost:5432/g10_hapi_db
username: postgres
password: admin
driver-class-name: org.postgresql.Driver
```

## To test from local
1. Setup ngrok tool on local - https://ngrok.com/ - you might need to signin / login to create a free account on this
2. Open the ngrok tool and run the command - ngrok http https://localhost:8080
3. ngrok will give you a public facing URL

## Visual Inspection Testing

1. Launch the URL - https://<ur_ngrok_url>/auth/register-app and you will get an image like below
   <img width="668" height="289" alt="image" src="https://github.com/user-attachments/assets/03490cd0-1b37-49f1-a147-5ac645494585" />
2. If you leave the scope as it is by default (i.e)
```
launch launch/patient patient/*.read openid fhirUser profile offline_access
```
Then it will behave as Single Patient Application Registration process as mentioned in the visual attestation - **11.01 Health IT Module demonstrated support for application registration for Single patients.**

3. Upon registration you will receive a client ID and secret key. Note, it will just be a one time appearence. Save it.

4. If you register the application with the scope as 
```
system/*.rs
```
Then, it will be have as Multi Patient Application Registration process as mentioned in the visual attestation - **11.01 Health IT Module demonstrated support for application registration for Multiple patients.**

5. If you register the application as single patient then  the understanding is that in inferno testing the Multi-Patient testing should fail.
6. If you register the application as Multiple Patient then the understanding is both single patient and multi-patient should be working.

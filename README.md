# CT watcher
Light Watcher: The tool for inspecting third-party monitors in the CT framework.

## Environment configuration

Install python3 (we use Python 3.7) and pip. 

```bash
pip install psycopg2-binary (we used version 2.8.4)
pip install pyOpenSSL (we used version 19.1.0)
pip install urllib3 (we used version 1.26.8)
pip install publicsuffixlist (we used version0.6.13)
pip install schedule (we used version 0.6.0)
pip install censys (we used version 2.2.3)
```

Make sure the network can access the responsive service (e.g., Facebook Graph API).

## config.py

Configure the folder address for storing data after "DATA_ROOT_FOLDER".

Fill in the APP token of Facebook Graph API (https://developers.facebook.com/tools/explorer/) after "FACEBOOK_TOKEN".

Fill in the API Key of SSLMate (https://sslmate.com/certspotter/) after "SSLMATE_TOKEN".

We give recommended parameters for the rest of the configuration items.

### Spare token

We provide some spare tokens in the "spare-facebook-token.json" and the "spare-sslmate-token.json". Reviewers can use these tokens without registering new accounts.

Since the tokens provided are all generated by free accounts, there are certain limitations on the query speed (i.e., SSLMate Spotter limits 10 queries per hour and Facebook Monitor limits 200 queries per hour). Therefore, if there are related errors (e.g., "rate_limited") in the "journal.txt" file, you need to replace the token with a new one or wait for a while.

## domain.csv

Fill in the domains in the "domains.csv" file as the input to watcher.

### Test case

Due to the limited query speed, it is recommended to only fill in a few domains and not to fill in large domains (e.g., "amazon.com", "microsoft.com", "netflix.com", "qq.com"). We give two test cases in "domains.csv".

## run code

python3 main.py

## tips

Google Monitor is currently out of service, and Entrust Search has an anti-crawler mechanism. Besides, obtaining the required data from Censys is expensive.
Therefore, this watcher prototype contains 3 third-party monitors, namely crt.sh, Facebook Monitor and SSLMate Spotter. 

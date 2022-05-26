# CTWatcher
Auditing tool for third-party monitors in the CT framework.

# Environment configuration

Install python3 and pip.

pip3 install psycopg2-binary

pip3 install pyOpenSSL

pip3 install censys

pip3 install urllib

pip3 install publicsuffixlist

Configure your Censys credentials, see https://pypi.org/project/censys/

Make sure the network can access the responsive service (e.g., Facebook Graph API).

# CTWatcher configuration

## config.py

Configure the folder address for storing data after "DATA_ROOT_FOLDER".

Fill in the APP token of Facebook Graph API (https://developers.facebook.com/tools/explorer/) after "FACEBOOK_TOKEN".

Fill in the API Key of SSLMate (https://sslmate.com/certspotter/) after "SSLMATE_TOKEN".

We give recommended parameters for the rest of the configuration items.

## domain.csv

Fill in the domains that is the input to CTWatcher.

## run code

python3 main.py

## tips

The free account has a query limit, so we recommend not to enter a large domain (e.g., "amazon.com", "microsoft.com", "netflix.com", etc.) as input, otherwise it will take a very long time.

In the source code we give some examples of features.

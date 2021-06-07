# OAuzz
The fuzzer for evaluating the security of OAuth based web services

## Original Project URL

https://code.google.com/archive/p/oauzz/

## Descripcion

OAuzz is a fuzzer which allows to check the security of OAuth based web services.

It has been implemented based on [RFC 5849](https://www.ietf.org/rfc/rfc5849.txt) and on [OAuth Request Body Hash 1.0 Draft 4](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html).

OAuzz supports the **three signature algorithms** of OAuth 1.0 (PLAINTEXT, HMAC-SHA1 and RSA-SHA1) and implements the extra OAuth parameter **oauth_body_hash** to allow integrity checks on HTTP request bodies with content types other than `application/x-www-form-urlencoded`.

## Usage

OAuzz implements a console user interface which makes it easily configurable.

![](http://1.bp.blogspot.com/-uvxax5Ao7uU/T-W9BvzK_cI/AAAAAAAAAQ8/EgCnuL8e5gU/s320/01+Welcome.png)

### Commands

The OAuzz commands are:

| Command | Description | 
|:--------|:------------| 
| set VARIABLE VALUE | Set VARIABLE to VALUE. | 
| unset [VARIABLE/S] | Unset VARIABLE (or all of them). | 
| show [VARIABLE/S] | Show the value of VARIABLE (or all of them). | 
| authenticate | OAuth Authentication with the server (default 3-legged). | 
| test | Send a request with the correct values of each parameter. | 
| fuzz | Run the fuzzer. | 
| select | Perform a SQL Select query over the fuzzing results. | 
| export | Export the database results to CSV, XML or HTML format. | 
| help [COMMAND] | This help or the specified command help. | 
| version | Show the version. | 
| exit | Terminate the application. |

There are different types of variables to configure different parameters of the application.

### OAuth variables

They configure all the possible OAuth parameters which are used to sign the request.

| Variable | Fuzzable | Description | 
|:---------|:---------|:------------| 
| CONSUMERKEY | YES | Consumer key. | 
| CONSUMERSECRET | YES | Consumer secret. | 
| TOKENKEY | YES | Token key which identifies the user (unset it for 2-legged OAuth). | 
| TOKENSECRET | YES | Token secret (unset it for 2-legged OAuth). | 
| SIGNATUREMETHOD | YES | OAuth Signature Method. Possible values: PLAINTEXT, HMAC-SHA1 (default), RSA-SHA1. | 
| VERSION | YES | OAuth version (default "1.0"). | 
| TIMESTAMP | YES | OAuth timestamp (unset it if you want the current time). | 
| NONCE | YES | OAuth nonce (unset it if you want to use a random one for each request). | 
| EXTRAOAUTHPARAM | YES | Extra OAuth parameters to be included in the OAuth header. | 
| BODYHASH | NO | Flag which determines if "oauth_body_hash" must be included as a OAuth parameter. Possible values: True or False (default). | 
| OAUTHCALLBACK | NO | Used while the OAuth authentication process, in the getRequestToken request. To fuzz this value configure it like an EXTRAOAUTHPARAM parameter. | 
| AUTHORITATIONURL | NO | Used while the OAuth authentication process. It is the Service Provider URL where the final user must authorize the App. To fuzz this value configure it like an EXTRAOAUTHPARAM parameter. | 
| CERTPATH | NO | Digital certificate to use with RSA-SHA1 signature mode. |

### HTTP variables
They configure the HTTP parameters which allow create the HTTP Request.

| Variable | Fuzzable | Description | 
|:---------|:---------|:------------| 
| METHOD | YES | HTTP method (default GET). | 
| URL | YES | URL of the service (without any parameters). | 
| URLPARAM | YES | Parameters used in the URL. Use one SET command per parameter. | 
| HEADER | YES | Extra HTTP header to use in the request. Use one SET command per header. | 
| BODY | YES | Body of the request (if needed). Leave it in blank to set up a MULTIPART body. | 
| BODYTYPE | NO | Defines the Content-Type through different values: URLENCODED, MULTIPART or OTHER (used for JSON, XML or other types). | 
| REALM | YES | If setted up, it was used to create the Authorization HTTP header. | 
| PROXY | NO | HTTP proxy through you want to send the requests. |

### Other variables
Internal OAuzz variables.

| Variable | Fuzzable | Description | 
|:---------|:---------|:------------| 
| FUZZFILE | NO | Specify a file with fuzzing rules (default oauzz.dict). | 
| RESULTFILE | NO | Common part of the results files name (default: results). |

### How to fuzz
The variables marked as fuzzable can be fuzzable (obviously).

To fuzz them, they have to be setted up using the word "FUZZ" wherever you want to fuzz.

The following example will fuzz the variable BODY in two different points:

```
OAuzz > set BODY param1=FUZZ&param2=FUZZ&param3=this_is_not_fuzzable 
Set the original value for FUZZ pattern 1: fuzzable_value_1 
Set the original value for FUZZ pattern 2: fuzzable_value_2 
BODY = param1=fuzzable_value_1&param2=fuzzable_value_2&param3=this_is_not_fuzzable 

OAuzz > show BODY 
BODY = param1=FUZZ&param2=FUZZ&param3=this_is_not_fuzzable 

OAuzz >
```

### Usage Example
OAuzz supports input scripts, so you can write your own scripts using the OAuzz syntax to launch your tests automatically.

One script example is the file 'script.txt':

```
python OAuzz_v1.0.py script.txt
```

### Configure a proxy

```
set PROXY http://127.0.0.1:8080
```

### Set the application credentials

```
set CONSUMERKEY myConsumerKey 
set CONSUMERSECRET myConsumerSecret
```

### Set the user credentials

```
set TOKENKEY myUserToken 
set TOKENSECRET myUserSecret
```

### Set the URL to fuzz

```
set URL "https://www.example.com/getProfile/user:FUZZ"
```

### Launch the fuzzer

```
fuzz
```


The way to call OAuzz with an input script (you can put as many as you want) is:

```
$ python OAuzz_v1.0.py script.txt
```

The fuzzable parameters will be asked when you execute the script:

![](http://3.bp.blogspot.com/-zNPo2OcQoZA/T-XBFyKGCqI/AAAAAAAAARI/fdbTkP_isc4/s320/02+Launching_script.png)

And later the script will continue its execution launching the fuzzer:

![](http://1.bp.blogspot.com/-_bYMBKL3qsg/T-XBHi8ddRI/AAAAAAAAARQ/8lXUItDp0Yk/s320/03+Fuzzing.png)

That is the easiest way but not the only one of use OAuzz. Using the console UI, you can do the same typing each command in the OAuzz console.

# Contact

Web: http://laxmarcaellugar.blogspot.com/

Mail: bloglaxmarcaellugar , which is a email address of gmail.com

Google+: La X marca el lugar

twitter: @laXmarcaellugar




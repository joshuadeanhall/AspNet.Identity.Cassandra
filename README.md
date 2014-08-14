AspNet.Identity.Cassandra
=========================
The initially release is now complete.  Please create an issue (or pull request) for any problems you find with the code and I will work through them as quickly as possible.  

## Installation ##
Run the following commands from the package manager to remove the entity framework identity provider and to install the Cassandra identity provider.

```PowerShell
Uninstall-Package Microsoft.AspNet.Identity.EntityFramework
Uninstall-Package EntityFramework
Install-Package AspNet.Identity.Cassandra
```
Once installed you will need to make some modification to the AccountController.


When setting up the identity you can either have the library create the tables for you or you can create the tables yourself.  To setup the tables manually initialize CassandraUserStore with
createSchema = false and to run the cql script in defaultschema.cql.

The script will create the following tables

First Header    | Second Header
------------- | -------------
Content Cell  | Content Cell
Content Cell  | Content Cell


users 
------------- 
userid uuid  (Primary Key)
username text
password_hash text
security_stamp text
two_factor_enabled boolean
access_failed_count int
lockout_enabled boolean
lockout_end_date timestamp
phone_number text
phone_number_confirmed boolean
email text
email_confirmed boolean

users_by_username

column        	| type    	| key 
------------- 	| ------- 	| --------
username      	| text		| PK
userid 			| uuid		|
password_hash 	| text		|
security_stamp	| text		|
two_factor_enabled	| boolean	|	
access_failed_count	| int	|
lockout_enabled	| boolean	|
lockout_end_date	| timestamp	|
phone_number	| text		|
phone_number_confirmed	| boolean	|
email			| text	|
email_confirmed	| boolean	|


users_by_email 


column			| type		| key
---------------	| ---------	| ------
email 			| text		| PK
userid 			| uuid		|
username 		| text		|
password_hash 	| text		|
security_stamp 	| text		|
two_factor_enabled	| boolean	|
access_failed_count	| int	|
lockout_enabled	| boolean	|
lockout_end_date	| timestamp |
phone_number	| text		|
phone_number_confirmed	| boolean	|
email_confirmed	| boolean	|


logins 

column			| type		| key
---------------	| ---------	| ------
userid	| uuid	| PK1
login_provider	| text	| PK2
provider_key 	| text | PK3
    PRIMARY KEY(userid, login_provider, provider_key)




logins_by_provider


column			| type		| key
---------------	| ---------	| ------
login_provider 	| text	| PK1
provider_key 	| text	| PK2
userid 			| uuid 	|


claims 

column			| type		| key
---------------	| ---------	| ------
userid			| uuid		| PK1
type 			| text		| PK2
value 			| text		| PK3

 

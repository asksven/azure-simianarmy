# azure-simianarmy

is licensed unter the terms of the Apache 2.0 license (https://www.apache.org/licenses/LICENSE-2.0)

This project intends at providing a set of scripts that can be run against a Microsoft Azure environment to check a defined level of conformity to defined rules and verify the security state of the environment. This idea is not new and was borrowed from Netflix (http://techblog.netflix.com/2011/07/netflix-simian-army.html).

The security state of the environment is validated using introspection as well as the Azure Security Center API.
The (future) conformity state aims at validating the the environment is configured following given rules like the mandatory use of storage encryption, database encryption, least priviledge access, etc. 

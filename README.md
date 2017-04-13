# basicAuthApiGateway

Lambda for basic authentication with aws Api Gateway. 

## Prerequisites

* Api created with Api Gateway
* A lambda function containing this implementation
* Custom Authorizer
  * pick your lambda's region
  * pick your lambda
  * set your authorizer's name
  * pick your arn policy
  * choose method.request.header.Authorization as Idendity token source

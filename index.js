var credentialsRegExp = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9\-\._~\+\/]+=*) *$/;
var userPassRegExp = /^([^:]*):(.*)$/;

Credentials = function(name, pass) {
  this.name = name;
  this.pass = pass;
}

exports.handler = (event, context, callback, config) => {
  var token = event.authorizationToken;
  var user = userFromBasicAuthString(token);

  if (user.name === process.env.AUTH_USER && user.pass === process.env.AUTH_PASS) {
    console.log("Authorized for name: " + user.name + " and methodArn: " + event.methodArn);
    context.succeed(generatePolicy(user.name, 'Allow', event.methodArn));
    return;
  }
  
  context.fail("Unauthorized");
};

userFromBasicAuthString = (header) => {
  var match = credentialsRegExp.exec(header || '');

  if (!match) {
    if (!header) {
      console.log('no header provided');
      return null;
    }
    match = ['', header];
  }

  var userPass = userPassRegExp.exec(decodeBase64(match[1]));

  if (!userPass) {
    console.log("No user password provided");
    return null;
  }

  return new Credentials(userPass[1], userPass[2]);
}

decodeBase64 = (str) => {
  return new Buffer(str, 'base64').toString();
}

generatePolicy = (principalId, effect, resource) => {
  var authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = '2012-10-17'; // default version
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke'; // default action
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  console.log(JSON.stringify(authResponse));
  return authResponse;
}

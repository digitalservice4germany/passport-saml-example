var http = require('http');
var fs = require('fs');
var express = require("express");
var dotenv = require('dotenv');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');
var xml_1 = require("passport-saml/lib/node-saml/xml");
var base64url = require('base64url');

dotenv.load();

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var samlStrategy = new saml.Strategy({
  // URL that goes from the Identity Provider -> Service Provider
  callbackUrl: process.env.CALLBACK_URL,
  // URL that goes from the Service Provider -> Identity Provider
  entryPoint: process.env.ENTRY_POINT,
  // Usually specified as `/shibboleth` from site root
  issuer: process.env.ISSUER,
  identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  // Service Provider private key for decryption of encrypted assertions
  decryptionPvk: fs.readFileSync(__dirname + '/cert/sp_key.pem', 'utf8'),
  // Service Provider private key for signing requests
  privateKey: fs.readFileSync(__dirname + '/cert/sp_key.pem', 'utf8'),
  // Service Provider public key to be included in AuthnRequest
  signingCert: fs.readFileSync(__dirname + '/cert/sp_cert.pem', 'utf8'),
  // Identity Provider public key for signature validation
  cert: fs.readFileSync(__dirname + '/cert/idp_cert.pem', 'utf8'),
  validateInResponseTo: false,
  disableRequestedAuthnContext: true,
  authnRequestBinding: 'HTTP-POST',
  forceAuthn: true,
  signatureAlgorithm: 'sha256',
  digestAlgorithm: 'sha256',
  skipRequestCompression: true
}, function(profile, done) {
  return done(null, profile);
});

passport.use(samlStrategy);

var app = express();

app.use(cookieParser());
app.use(bodyParser());
app.use(session({secret: process.env.SESSION_SECRET}));
app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated())
    return next();
  else
    return res.redirect('/login');
}

app.get('/',
  ensureAuthenticated, 
  function(req, res) {
    let response = buildResponse(req.query.samlResponse);
    res.setHeader("Content-Type", "text/html")
    res.send(response);
  }
);

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function (req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  async function(req, res) {
    let samlResponse = req.body.SAMLResponse;
    if (samlResponse) {
      let result = await extractData(samlResponse);
      res.redirect('/?samlResponse=' + base64url(JSON.stringify(result)));
    } else {
      res.redirect('/');
    }
  }
);

app.get('/login/fail', 
  function(req, res) {
    res.status(401).send('Login failed');
  }
);

//general error handler
app.use(function(err, req, res, next) {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});

var server = app.listen(4006, function () {
  console.log('Listening on port %d', server.address().port)
});

async function extractData(samlResponse) {
  let result = [];
  const xmlResponse = Buffer.from(samlResponse, "base64").toString("utf8");
  const responseDoc = (0, xml_1.parseDomFromString)(xmlResponse);
  const encryptedAssertions = xml_1.xpath.selectElements(responseDoc, "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");
  const encryptedAssertionXml = encryptedAssertions[0].toString();
  const decryptedXml = await (0, xml_1.decryptXml)(encryptedAssertionXml, fs.readFileSync(__dirname + '/cert/sp_key.pem', 'utf8'));
  const decryptedDoc = (0, xml_1.parseDomFromString)(decryptedXml);

  const attributes = xml_1.xpath.selectElements(decryptedDoc, "/*[local-name()='Assertion']/*[local-name()='AttributeStatement']/*[local-name()='Attribute']");
  attributes.forEach(attribute => {
    let name = attribute.getAttribute("Name");
    let valueNode = attribute.childNodes[0];
    let valueChildNodes = valueNode.childNodes;
    let value = "";

    if (valueChildNodes.length === 1) {
      value = valueChildNodes[0].nodeValue;
    } else {
      for (let i = 0; i < valueChildNodes.length; i++) {
        let localName = valueChildNodes[i].localName;
        let localValue = valueChildNodes[i].childNodes[0].nodeValue;
        value += valueChildNodes[i].childNodes[0].nodeValue + " ";
        result.push({name: localName, value: localValue});
      }
    }
    result.push({name: name, value: value});
  })
  return result;
}

function buildResponse(samlResponse) {
  let html = '<div style="font-family: \'Open Sans\', sans-serif;"><h1 style="padding: 0.5rem 1rem;">Authenticated</h1>';
  if (samlResponse) {
    html += '<br><table><thead style="font-weight: bold;"><tr><td style="padding: 0.5em 1em;">Attribute</td><td style="padding: 0.5em 1em;">Value</td></tr></thead><tbody>';
    let data = JSON.parse(base64url.decode(samlResponse));
    data.forEach(attr => {
      html += '<tr><td style="padding: 0.5em 1em;">' + attr.name + '</td><td style="padding: 0.5em 1em;">' + attr.value + '</td></tr>'
    });
    html += '</tbody></table>';
  }
  html += '</div>';
  return html;
}
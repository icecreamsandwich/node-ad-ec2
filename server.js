var saml2 = require('saml2-js');
var fs = require('fs');
var express = require('express');
var app = express();
var path = require("path");
var ActiveDirectory = require('activedirectory');
var crypto = require('crypto');
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: true }));

// Create service provider
var sp_options = {
  //entity_id: "https://sp.example.com/metadata.xml",
  entity_id: "https://192.168.1.162/saml/login",
  //private_key: fs.readFileSync("key-file.pem").toString(),
  //certificate: fs.readFileSync("cert-file.crt").toString(),
  assert_endpoint: "https://192.168.1.162/saml/acs",
  //assert_endpoint: "https://sp.example.com/assert"
};
var sp = new saml2.ServiceProvider(sp_options);
 
// Create identity provider
var idp_options = {
  sso_login_url: "https://adfs.gasf.com/adfs/ls/idpinitiatedsignon.aspx",
  sso_logout_url: "https://adfs.gasf.com/adfs/ls/idpinitiatedsignon.aspx",
  /* sso_login_url: "https://idp.example.com/login",
  sso_logout_url: "https://idp.example.com/logout", */
  //certificates: [fs.readFileSync("cert-file1.crt").toString(), fs.readFileSync("cert-file2.crt").toString()]
};
var idp = new saml2.IdentityProvider(idp_options);
 
// ------ Define express endpoints ------
 
// Endpoint to retrieve metadata
app.get("/metadata.xml", function(req, res) {
  res.type('application/xml');
  res.send(sp.create_metadata());
});
 
// Starting point for login
app.post("/login", function(req, res) {
  /* sp.create_login_request_url(idp, {}, function(err, login_url, request_id) {
    if (err != null)
      return res.send(500);
    res.redirect(login_url);
  }); */
//console.log(req.body.username + req.body.password);return false;
var config = { url: 'ldap://ec2-54-89-136-67.compute-1.amazonaws.com',
               baseDN: 'CN=Users,DC=ec2-54-89-136-67,DC=compute-1,DC=amazonaws,DC=com',
               username: 'rajiv',
               password: 'tech121login*' }

      //get all users of a group
      /* var groupName = 'users';
      var dn = 'CN=Users,DC=ad,DC=gasf,DC=com'
      
      // Find group by common name
      var ad = new ActiveDirectory(config);
      ad.findGroup(groupName, function(err, group) {
        if (err) {
          console.log('ERROR: ' +JSON.stringify(err));
          return;
        }
      
        if (! group) console.log('Group: ' + groupName + ' not found.');
        else {
          console.log(group);
          console.log('Members: ' + (group.member || []).length);
        }
      });
 */
      var ad = new ActiveDirectory(config);
      var username = req.body.username;
      var password = req.body.password;
 
    ad.authenticate(username, password, function(err, auth) {
        if (err) {
          console.log('ERROR: '+JSON.stringify(err));
          return;
        }
        
        if (auth) {
          console.log('Authenticated!');
          // Example
          var password = 'rahul.u@piserve.com';
          //console.log(getSSOUrl(username, password));return false;
          res.redirect(getSSOUrl(username, password))
          //console.log(getSSOUrl(username, password));	// Under express, use something like res.redirect(getSSOUrl('Name', 'email'));
        }
        else {
          console.log('Authentication failed!');
         // res.redirect("/"); 
        }
    });
  //  res.redirect("/");    

});
 
// Assert endpoint for when login completes
app.post("/assert", function(req, res) {
  var options = {request_body: req.body};
  sp.post_assert(idp, options, function(err, saml_response) {
    if (err != null)
      return res.send(500);
 
    // Save name_id and session_index for logout
    // Note:  In practice these should be saved in the user session, not globally.
    name_id = saml_response.user.name_id;
    session_index = saml_response.user.session_index;
 
    res.send("Hello #{saml_response.user.name_id}!");
  });
});
 
// Starting point for logout
app.get("/logout", function(req, res) {
  var options = {
    name_id: name_id,
    session_index: session_index
  };
 
  sp.create_logout_request_url(idp, options, function(err, logout_url) {
    if (err != null)
      return res.send(500);
    res.redirect(logout_url);
  });
});

function autoRedirect(req,res,next){
      res.sendFile(path.resolve(__dirname, "build", "index.html"));
}

//Landing
app.get("/", autoRedirect, function(req, res){
    res.sendFile(path.resolve(__dirname, "build", "index.html"));
 });
//Public files <this needs to stay right below app.get("/")!!!!
app.use(express.static(__dirname + "/build")) 
 
app.listen(8081, () => console.log(`Listening on port 8081`));
//app.listen(3031);

  /**
	 * Generates and returns a Freshdesk Single Sign On URL
	 * {@link https://gist.github.com/derekseymour/26a6fe573c1274642976 Gist}
	 *
	 * @author Derek Seymour <derek@rocketideas.com>
	 * @param {String} name - The name of the user logging in.
	 * @param {String} email - A valid email address to associate with the user.
	 * @param {String} [redirect_to] - An optional URL to redirect to after logging in.
	 * @returns {String} Freshdesk SSO URL.
	 */
	function getSSOUrl(name, email, redirect_to) {
		var freshdesk_secret = '046926591b0f9b31d43628f3b204ad3c';
		var freshdesk_base_url = 'https://piserveassist.freshdesk.com';

		var timestamp = Math.floor(new Date().getTime() / 1000).toString();
		var hmac = crypto.createHmac('md5', freshdesk_secret);
		hmac.update(name + freshdesk_secret + email + timestamp);
		var hash = hmac.digest('hex');
		return freshdesk_base_url + '/login/sso/' +
			'?name=' + escape(name) +
			'&email=' + escape(email) +
			'&timestamp=' + escape(timestamp) +
			'&hash=' + escape(hash) +
			( typeof(redirect_to) === 'string' ? '&redirect_to=' + escape(redirect_to) : '' );
	}
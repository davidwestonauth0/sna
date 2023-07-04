'use latest';

const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const csurf = require('csurf');
const moment = require('moment');
const jwt = require('jsonwebtoken');
const request = require('request');
const ejs = require('ejs');
const _ = require('lodash');

const PORT = process.env.PORT || 5000

const app = express();

app.use(cookieSession({
  name: 'session',
  secret: 'shhh...',
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

const csrfProtection = csurf();

app.post('/callback',  (req, res) => {
      console.log(req.body);
       const formData = _.omit(req.body, '_csrf');
      const HTML = renderReturnView({
        action: `https://${process.env.AUTH0_CUSTOM_DOMAIN}/continue?state=${req.session.state}`,
        formData
      });


      // clear session
      req.session = null;

      res.set('Content-Type', 'text/html');
      res.status(200).send(HTML);

});


app.post('/', (req, res) => {
    var sessionToken = createOutputToken(req.body.sna_response, req.session.state, req.session.subject);

           const formData = _.omit(sessionToken, '_csrf');
          const HTML = renderReturnView({
            action: `https://${process.env.AUTH0_CUSTOM_DOMAIN}/continue?state=${req.session.state}&session_token=${req.session.session_token}`,
            session_token: sessionToken
          });


          // clear session
          req.session = null;

          res.set('Content-Type', 'text/html');
          res.status(200).send(HTML);

//    request.post({ url: `https://${process.env.AUTH0_CUSTOM_DOMAIN}/continue?state=${req.session.state}&session_token=${sessionToken}` }
//                   , function(error, response, body){
//       //console.log(body);
//             // clear session
//             req.session = null;
//
//             res.set('Content-Type', 'text/html');
//             res.status(200).send(HTML);
//    });


});


app.get('/', verifyInputToken, csrfProtection, (req, res) => {
  // get required fields from JWT passed from Auth0 rule
  // store data in session that needs to survive the POST
  req.session.subject = req.tokenPayload.sub;
  req.session.state = req.query.state;

  // render the profile form
  const data = {
    subject: req.tokenPayload.sub,
    csrfToken: req.csrfToken(),
    fields: {},
    action: req.originalUrl.split('?')[0]
  };
  data.fields.sna_url = req.tokenPayload.snaUrl;

    console.log(req.tokenPayload);


  const html = renderProfileView(data);

  res.set('Content-Type', 'text/html');
  res.status(200).send(html);
});

const parseBody = bodyParser.urlencoded({ extended: false });



// module.exports = fromExpress(app);

app.listen(PORT, () => console.log(`Listening on ${ PORT }`))

// middleware functions

function createOutputToken(sna_result, state, subject) {

  var payload = {}

  payload["iat"] = Math.floor(new Date().getTime()/1000);
  payload["state"] = state;
  payload["sub"] = subject;
  payload["exp"] = Math.floor((new Date().getTime() + 60 * 60 * 1000)/1000);
  payload["sna_result"] = sna_result;
  encoded = jwt.sign(payload, process.env.SECRET, { algorithm: 'HS256' });
  console.log(payload)
  //jwt.encode(payload, process.env.SECRET, algorithm="HS256")
  return encoded

}

function verifyInputToken(req, res, next) {
  const options = {
    issuer: process.env.ISSUER,
    audience: process.env.ISSUER
  }

  try {
    req.tokenPayload = jwt.verify(req.query.token, process.env.SECRET, options);
  } catch (err) {
    return next(err);
  }
  return next();
}

// view functions

function renderProfileView(data) {
  const template = `
<!DOCTYPE html>
<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
<style>
.loader {
  border: 16px solid #f3f3f3; /* Light grey */
  border-top: 16px solid #3498db; /* Blue */
  border-radius: 50%;
  width: 120px;
  height: 120px;
  animation: spin 2s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
</head>
<body>
<h1>Checking with phone network...</h1>
<div class="loader"></div>
      <form id="return_form" method="post" action="<%= action %>">
        <input type="hidden" id="sna_response" name="sna_response" value="">
      </form>



<script>

//<iframe id="sna_frame" src="<%= fields.sna_url %>" style="display:none">
//</iframe>

function checkIframeLoaded() {
    // Get a handle to the iframe element
    var iframe = document.getElementById('sna_frame');
    var iframeDoc = iframe.contentDocument || iframe.contentWindow.document;

    // Check if loading is complete
    if (  iframeDoc.readyState  == 'complete' ) {
        //iframe.contentWindow.alert("Hello");
        iframe.contentWindow.onload = function(){
            console.log("I am loaded");
        };
        // The loading is complete, call the function we want executed once the iframe is loaded
        afterLoading();
        return;
    }

    // If we are here, it is not loaded. Set things up so we check   the status again in 100 milliseconds
    window.setTimeout(checkIframeLoaded, 100);
}

function afterLoading(){
    console.log("I am here");
    document.getElementById('sna_response').value = "DONE";
                var form = document.getElementById('return_form');
    setTimeout(() => {form.submit(); }, 5000);


}

window.addEventListener("DOMContentLoaded", (event) => {
  console.log("DOM fully loaded and parsed");
  checkIframeLoaded();
});


async function hitSna(url) {
  try {
    const response = await fetchWithTimeout(url, {
      timeout: 6000
    });
    const games = await response;
    console.log("here");
    console.log(games);
    return games;
  } catch (error) {
    // Timeouts if the request takes
    // longer than 6 seconds
    console.log(error.name === 'AbortError');
  }
}
//var response = hitSna("<%= fields.sna_url %>");
//console.log(response);

//$.ajax({
//  type: "GET",
//  async: false,
//  url: "<%= fields.sna_url %>",
//  success: function (result) {
//     console.log(result);
//  }
//});

//const response = fetch("<%= fields.sna_url %>", {
//method: 'POST'
//});
//
//response.then(function(response) {
//             return response.text();
//           }).then(function(data) {
//             console.log(data); // this will be a string
//           });

//window.location.replace = "<%= fields.sna_url %>";
//window.location.assign = "<%= fields.sna_url %>";
//    const xhr = new XMLHttpRequest();
//    xhr.open("POST", "<%= fields.sna_url %>");
//    xhr.send();
//    //xhr.responseType = "text";
//    xhr.onload = () => {
//      if (xhr.readyState == 4 && xhr.status == 200) {
//        console.log(xhr);
//        console.log(xhr.responseText);
//        console.log(xhr.status);
//        var responseMessage = xhr.response;
//        if (responseMessage === "") {
//            responseMessage = "Unknown";
//        }
//        document.getElementById('sna_response').value = responseMessage;
//        var form = document.getElementById('return_form');
//        form.submit();
//      } else {
//        console.log(xhr.status);
//      }
//    };

const xhr = new XMLHttpRequest();
xhr.open('GET', '<%= fields.sna_url %>', false);

try {
  xhr.send();
  if (xhr.status != 200) {
    console.log('ERROR');
  } else {
    console.log(xhr.response);
  }
} catch(err) { // instead of onerror
  console.log("Request failed");
}

</script>

</body></html>`;

  return ejs.render(template, data);
}



function renderReturnView (data) {
  const template = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
    </head>

    <body>
      <form id="return_form" method="post" action="<%= action %>">
        <input type="hidden" id="session_token" name="session_token" value="<%= session_token %>">
      </form>
      <script>
        // automatically post the above form
        var form = document.getElementById('return_form');
        form.submit();
      </script>
    </body>
    </html>
  `;

  return ejs.render(template, data);
}
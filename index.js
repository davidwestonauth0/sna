'use latest';

const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const csurf = require('csurf');
const moment = require('moment');
const jwt = require('jsonwebtoken');
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

    data.fields.email = req.tokenPayload.sub;
    data.fields.domain = process.env.AUTH0_CUSTOM_DOMAIN;
    data.fields.clientID = process.env.AUTH0_CLIENT_ID;
    data.fields.redirectUri = process.env.AUTH0_REDIRECT_URI;

  const html = renderProfileView(data);

  res.set('Content-Type', 'text/html');
  res.status(200).send(html);
});

const parseBody = bodyParser.urlencoded({ extended: false });

app.post('/', parseBody, csrfProtection, (req, res) => {

  // render form that auth-posts back to Auth0 with collected data
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

// module.exports = fromExpress(app);

app.listen(PORT, () => console.log(`Listening on ${ PORT }`))

// middleware functions

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
  <script src="https://cdn.auth0.com/js/auth0/9.14/auth0.min.js"></script>

  <script>

    var params = Object.assign({
            overrides: {
                __tenant: "<%= fields.domain %>",
                __token_issuer: "<%= fields.domain %>"
            },
            domain: "<%= fields.domain %>",
            clientID: "<%= fields.clientID %>",
            redirectUri: "<%= fields.redirectUri %>",
            responseMode: 'form_post',
            responseType: 'token id_token'
        });

    var webAuth = new auth0.WebAuth(params);

    </script>
  <title>Auth0 Playground Custom Login Form</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1,user-scalable=0">

  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.0.7/css/all.css">
  <link href="chrome-extension://aeblfdkhhhdcdjpifhhbdiojplfjncoa/inline/fonts/Inter-roman.var.woff2" rel="stylesheet">
  <style>
      * {
        box-sizing: border-box;
      }

      body {
        background-image: radial-gradient(white, rgb(200, 200, 200));
        font-family: 'ulp-font','-apple-system','BlinkMacSystemFont','Roboto,Helvetica',sans-serif;
        font-size: 14px;
        color: #0F151A;
        margin: 0;
      }
      .footer {
        background-color: rgb(120, 120, 120);
        position: absolute;
        bottom: 0;
        left: 0;
        padding: 16px 0;
        width: 100%;
        color: white;
        /* Use a high z-index for future-proofing */
        z-index: 10;
      }
      .footer ul {
        text-align: center;
      }
      .footer ul li {
        display: inline-block;
        margin: 0 4px;
      }
      .footer ul li:not(:first-of-type) {
        margin-left: 0;
      }
      .footer ul li:not(:first-of-type)::before {
        content: '';
        display: inline-block;
        vertical-align: middle;
        width: 4px;
        height: 4px;
        margin-right: 4px;
        background-color: white;
        border-radius: 50%;
      }
      .footer a {
        color: white;
      }


      a {
        color: #1E1EF0;
        text-decoration: none;
        font-weight: 500;
      }

      button {
        background-color: transparent;
        border: 1px solid #0F151A;
        border-radius: 5px;
        font-family: 'ulp-font','-apple-system','BlinkMacSystemFont','Roboto,Helvetica',sans-serif;
        font-size: 16px;
        font-weight: 700;
        margin: 5px auto;
        padding: 10px 10px 5px 5px;
        text-align: left;
        width: 100%;
      }

      button:disabled,
      button[disabled] {
        background-color: #3885ff;
      }

      input {
        outline: 0;
        color: #0F151A;
        width: 100%;
        display: block;
        padding: 0 15px;
        font-size: 14px;
        border-radius: 4px;
        background-color: transparent;
        border: 1px solid #0F151A;
        transition: border-color .3s linear;
        -o-transition: border-color .3s linear;
        -ms-transition: border-color .3s linear;
        -moz-transition: border-color .3s linear;
        -webkit-transition: border-color .3s linear;
        height: 55px;
        order: 2;
        font-family: 'ulp-font','-apple-system','BlinkMacSystemFont','Roboto,Helvetica',sans-serif;
      }

      input:focus {
        border-width: 2px;
        border-color: #081351;
      }

      input[type="email"]:invalid {
        box-shadow: none;
      }

      .input-error {
        border: 1px solid #E32424;
      }

      input:focus.input-error {
        border-color: #E32424;
      }

      @keyframes onAutoFillStart {
        from {
          /**/
        }

        to {
          /**/
        }
      }

      @keyframes onAutoFillCancel {
        from {
          /**/
        }

        to {
          /**/
        }
      }

      input:-webkit-autofill {
        animation-name: onAutoFillStart;
        -webkit-box-shadow: 0 0 0 30px white inset !important;
        -webkit-text-fill-color: #4D5054;
      }

      input:not(:-webkit-autofill) {
        animation-name: onAutoFillCancel;
      }

      h1 {
        color: #0F151A;
        font-weight: 700;
      }

      .text-center {
        text-align: center;
      }

      .container {
        width: 100%;
        margin: 0 auto;
        padding-left: 15px;
        padding-right: 15px;
      }

      .web-header {
        display: none;
      }

      .alert-error {
        font-size: 14px;
        font-weight: 500;
        line-height: 17px;
        color: #E32424;
      }

      .social-signin {
        margin-bottom: 45px;
      }

      .row {
        display: flex;
      }

      .col-xs-12 {
        width: 100%;
      }

      .col-sm-6 {
        width: 50%;
      }

      .col-sm-6:first-child {
        padding-right: 5px;
      }

      .col-sm-6:last-child {
        padding-left: 5px;
      }

      .block {
        display: block;
      }

      .full-width {
        width: 100%;
        padding: 0 !important;
      }

      .btn-social::before {
        content: "";
        height: 34px;
        margin-top: -5px;
        margin-right: 5px;
        cursor: pointer;
        width: 34px;
        display: inline-block;
        vertical-align: middle;
      }

      .btn-social:hover,
      .btn-social:focus {
        background: #3885ff;
        cursor: pointer;
      }

      .btn-social.btn-social-apple::before {
        background-image: url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzRweCIgaGVpZ2h0PSIzNHB4IiB2aWV3Qm94PSIwIDAgMzQgMzQiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDYzLjEgKDkyNDUyKSAtIGh0dHBzOi8vc2tldGNoLmNvbSAtLT4KICAgIDx0aXRsZT5hcHBsZTwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxnIGlkPSJ6IiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iTF9MUkMwMDMiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0yNS4wMDAwMDAsIC0xODIuMDAwMDAwKSI+CiAgICAgICAgICAgIDxnIGlkPSJCdXR0b24tQmFja2dyb3VuZCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMjAuMDAwMDAwLCAxNzcuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iYXBwbGUiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDUuMDAwMDAwLCA1LjAwMDAwMCkiPgogICAgICAgICAgICAgICAgICAgIDxyZWN0IGlkPSJSZWN0YW5nbGUtQ29weS00IiBmaWxsPSIjRkZGRkZGIiB4PSIwIiB5PSIwIiB3aWR0aD0iMzQiIGhlaWdodD0iMzQiIHJ4PSI0Ij48L3JlY3Q+CiAgICAgICAgICAgICAgICAgICAgPHBhdGggZD0iTTE2Ljg0NTcwMzEsMTIuMDUyNzM0NCBDMTcuMzA3OTQyNywxMi4wMTM2NzE5IDE3LjY1Mjk5NDgsMTEuOTU4MzMzMyAxNy44ODA4NTk0LDExLjg4NjcxODggQzE4LjIzODkzMjMsMTEuNzYzMDIwOCAxOC42MDAyNjA0LDExLjUyMjEzNTQgMTguOTY0ODQzOCwxMS4xNjQwNjI1IEMxOS4zODgwMjA4LDEwLjc0MDg4NTQgMTkuNjk3MjY1NiwxMC4yODE5MDEgMTkuODkyNTc4MSw5Ljc4NzEwOTM4IEMyMC4wODc4OTA2LDkuMjkyMzE3NzEgMjAuMTg1NTQ2OSw4LjgzNjU4ODU0IDIwLjE4NTU0NjksOC40MTk5MjE4OCBDMjAuMTg1NTQ2OSw4LjM1NDgxNzcxIDIwLjE4MjI5MTcsOC4yODk3MTM1NCAyMC4xNzU3ODEyLDguMjI0NjA5MzggQzIwLjE2OTI3MDgsOC4xNTk1MDUyMSAyMC4xNTI5OTQ4LDguMDg0NjM1NDIgMjAuMTI2OTUzMSw4IEMxOC45NjE1ODg1LDguMjY2OTI3MDggMTguMTI2NjI3Niw4Ljc2MTcxODc1IDE3LjYyMjA3MDMsOS40ODQzNzUgQzE3LjExNzUxMywxMC4yMDcwMzEyIDE2Ljg1ODcyNCwxMS4wNjMxNTEgMTYuODQ1NzAzMSwxMi4wNTI3MzQ0IFogTTE0LjQ4MjQyMTksMjQuNjY5OTIxOSBDMTQuODIwOTYzNSwyNC42Njk5MjE5IDE1LjI2MjA0NDMsMjQuNTU3NjE3MiAxNS44MDU2NjQxLDI0LjMzMzAwNzggQzE2LjM0OTI4MzksMjQuMTA4Mzk4NCAxNi44MjYxNzE5LDIzLjk5NjA5MzggMTcuMjM2MzI4MSwyMy45OTYwOTM4IEMxNy42NDY0ODQ0LDIzLjk5NjA5MzggMTguMTQ5NDE0MSwyNC4xMDM1MTU2IDE4Ljc0NTExNzIsMjQuMzE4MzU5NCBDMTkuMzQwODIwMywyNC41MzMyMDMxIDE5LjgwNzk0MjcsMjQuNjQwNjI1IDIwLjE0NjQ4NDQsMjQuNjQwNjI1IEMyMC45OTkzNDksMjQuNjQwNjI1IDIxLjg1ODcyNCwyMy45ODYzMjgxIDIyLjcyNDYwOTQsMjIuNjc3NzM0NCBDMjMuMjk3NTI2LDIxLjgwNTMzODUgMjMuNzA3NjgyMywyMC45Njg3NSAyMy45NTUwNzgxLDIwLjE2Nzk2ODggQzIzLjM2MjYzMDIsMTkuOTkyMTg3NSAyMi44MzUyODY1LDE5LjU3MjI2NTYgMjIuMzczMDQ2OSwxOC45MDgyMDMxIEMyMS45MTA4MDczLDE4LjI0NDE0MDYgMjEuNjc5Njg3NSwxNy40OTg2OTc5IDIxLjY3OTY4NzUsMTYuNjcxODc1IEMyMS42Nzk2ODc1LDE1LjkxNjY2NjcgMjEuODk3Nzg2NSwxNS4yMjY1NjI1IDIyLjMzMzk4NDQsMTQuNjAxNTYyNSBDMjIuNTc0ODY5OCwxNC4yNTY1MTA0IDIyLjk1NTcyOTIsMTMuODYyNjMwMiAyMy40NzY1NjI1LDEzLjQxOTkyMTkgQzIzLjEzMTUxMDQsMTIuOTk2NzQ0OCAyMi43ODMyMDMxLDEyLjY2MTQ1ODMgMjIuNDMxNjQwNiwxMi40MTQwNjI1IEMyMS44MDY2NDA2LDExLjk4NDM3NSAyMS4wOTM3NSwxMS43Njk1MzEyIDIwLjI5Mjk2ODgsMTEuNzY5NTMxMiBDMTkuODA0Njg3NSwxMS43Njk1MzEyIDE5LjIyODUxNTYsMTEuODgzNDYzNSAxOC41NjQ0NTMxLDEyLjExMTMyODEgQzE3LjkwMDM5MDYsMTIuMzM5MTkyNyAxNy40MjE4NzUsMTIuNDUzMTI1IDE3LjEyODkwNjIsMTIuNDUzMTI1IEMxNi45MDEwNDE3LDEyLjQ1MzEyNSAxNi40NDA0Mjk3LDEyLjM1MjIxMzUgMTUuNzQ3MDcwMywxMi4xNTAzOTA2IEMxNS4wNTM3MTA5LDExLjk0ODU2NzcgMTQuNDYyODkwNiwxMS44NDc2NTYyIDEzLjk3NDYwOTQsMTEuODQ3NjU2MiBDMTIuODI4Nzc2LDExLjg0NzY1NjIgMTEuODc5ODgyOCwxMi4zMjk0MjcxIDExLjEyNzkyOTcsMTMuMjkyOTY4OCBDMTAuMzc1OTc2NiwxNC4yNTY1MTA0IDEwLDE1LjUwMzI1NTIgMTAsMTcuMDMzMjAzMSBDMTAsMTguNjgwMzM4NSAxMC40OTE1MzY1LDIwLjM2MDAyNiAxMS40NzQ2MDk0LDIyLjA3MjI2NTYgQzEyLjQ1NzY4MjMsMjMuODA0MDM2NSAxMy40NjAyODY1LDI0LjY2OTkyMTkgMTQuNDgyNDIxOSwyNC42Njk5MjE5IFoiIGlkPSLvo78iIGZpbGw9IiMwMDAwMDAiIGZpbGwtcnVsZT0ibm9uemVybyI+PC9wYXRoPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=");
      }

      .btn-social.btn-social-facebook::before {
        background-image: url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzRweCIgaGVpZ2h0PSIzNHB4IiB2aWV3Qm94PSIwIDAgMzQgMzQiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDYzLjEgKDkyNDUyKSAtIGh0dHBzOi8vc2tldGNoLmNvbSAtLT4KICAgIDx0aXRsZT5mYWNlYm9vazwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxnIGlkPSJMaWdodC1Nb2RlIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iTF9MUkMwMDIiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0yNS4wMDAwMDAsIC0yMzYuMDAwMDAwKSI+CiAgICAgICAgICAgIDxnIGlkPSJCdXR0b24tQmFja2dyb3VuZCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMjAuMDAwMDAwLCAxNzcuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iZmFjZWJvb2siIHRyYW5zZm9ybT0idHJhbnNsYXRlKDUuMDAwMDAwLCA1OS4wMDAwMDApIj4KICAgICAgICAgICAgICAgICAgICA8cmVjdCBpZD0iUmVjdGFuZ2xlLUNvcHktNSIgZmlsbD0iI0ZGRkZGRiIgeD0iMCIgeT0iMCIgd2lkdGg9IjM0IiBoZWlnaHQ9IjM0IiByeD0iNCI+PC9yZWN0PgogICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik0yNS4wNjE2MjI2LDkgTDkuOTM3NTk5Miw5IEM5LjQxOTcwODI4LDkuMDAwMjU5NDMgOSw5LjQyMDM1Njc3IDksOS45MzgzNzc0MiBMOSwyNS4wNjI0MDA4IEM5LjAwMDI1OTQzLDI1LjU4MDI5MTcgOS40MjAzNTY3NywyNiA5LjkzODM3NzQyLDI2IEwyNS4wNjE2MjI2LDI2IEMyNS41Nzk3NzI5LDI2IDI2LDI1LjU4MDE2MiAyNiwyNS4wNjIwMTE3IEMyNiwyNS4wNjE4ODIgMjYsMjUuMDYxNzUyMyAyNiwyNS4wNjE2MjI2IEwyNiw5LjkzNzU5OTIgQzI1Ljk5OTc0MDYsOS40MTk3MDgyOCAyNS41Nzk2NDMzLDkgMjUuMDYxNjIyNiw5IFoiIGlkPSJQYXRoIiBmaWxsPSIjNDI2N0IyIiBmaWxsLXJ1bGU9Im5vbnplcm8iPjwvcGF0aD4KICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTkuNTQ3NjcxOCwyNiBMMTkuNTQ3NjcxOCwxOS4xNjczMjEyIEwyMS42MTk3MzM5LDE5LjE2NzMyMTIgTDIxLjkzMDE1NTIsMTYuNDkyOTE0MSBMMTkuNTQ3NjcxOCwxNi40OTI5MTQxIEwxOS41NDc2NzE4LDE0Ljc4OTU5NzEgQzE5LjU0NzY3MTgsMTQuMDE3MDY1NSAxOS43NDA1OTM4LDEzLjQ5MDY3NjQgMjAuNzM3MDk0NiwxMy40OTA2NzY0IEwyMiwxMy40OTA2NzY0IEwyMiwxMS4xMDUxNDMgQzIxLjc4MDI3OTksMTEuMDcyNjU2NSAyMS4wMjY0MTcsMTEgMjAuMTQ5MjM0MywxMSBDMTguMzE3NzQ4NywxMSAxNy4wNjQzMDE2LDEyLjI0MjMwNTIgMTcuMDY0MzAxNiwxNC41MjQ3MTc2IEwxNy4wNjQzMDE2LDE2LjQ5MjkxNDEgTDE1LDE2LjQ5MjkxNDEgTDE1LDE5LjE2NzMyMTIgTDE3LjA2NDMwMTYsMTkuMTY3MzIxMiBMMTcuMDY0MzAxNiwyNiBMMTkuNTQ3NjcxOCwyNiBaIiBpZD0iUGF0aCIgZmlsbD0iI0ZGRkZGRiIgZmlsbC1ydWxlPSJub256ZXJvIj48L3BhdGg+CiAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPg==");
      }

      .btn-social.btn-social-google::before {
        background-image: url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzRweCIgaGVpZ2h0PSIzNHB4IiB2aWV3Qm94PSIwIDAgMzQgMzQiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDYzLjEgKDkyNDUyKSAtIGh0dHBzOi8vc2tldGNoLmNvbSAtLT4KICAgIDx0aXRsZT5nb29nbGU8L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZyBpZD0iTGlnaHQtTW9kZSIgc3Ryb2tlPSJub25lIiBzdHJva2Utd2lkdGg9IjEiIGZpbGw9Im5vbmUiIGZpbGwtcnVsZT0iZXZlbm9kZCI+CiAgICAgICAgPGcgaWQ9IkxfTFJDMDAyIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgtMjUuMDAwMDAwLCAtMjkwLjAwMDAwMCkiPgogICAgICAgICAgICA8ZyBpZD0iQnV0dG9uLUJhY2tncm91bmQiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDIwLjAwMDAwMCwgMTc3LjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9Imdvb2dsZSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoNS4wMDAwMDAsIDExMy4wMDAwMDApIj4KICAgICAgICAgICAgICAgICAgICA8cmVjdCBpZD0iUmVjdGFuZ2xlLUNvcHktNiIgZmlsbD0iI0ZGRkZGRiIgeD0iMCIgeT0iMCIgd2lkdGg9IjM0IiBoZWlnaHQ9IjM0IiByeD0iNCI+PC9yZWN0PgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJHcm91cC0xNSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoOC4wMDAwMDAsIDguMDAwMDAwKSI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik0xNy42NCw5LjIwNDU0NTQ1IEMxNy42NCw4LjU2NjM2MzY0IDE3LjU4MjcyNzMsNy45NTI3MjcyNyAxNy40NzYzNjM2LDcuMzYzNjM2MzYgTDksNy4zNjM2MzYzNiBMOSwxMC44NDUgTDEzLjg0MzYzNjQsMTAuODQ1IEMxMy42MzUsMTEuOTcgMTMuMDAwOTA5MSwxMi45MjMxODE4IDEyLjA0NzcyNzMsMTMuNTYxMzYzNiBMMTIuMDQ3NzI3MywxNS44MTk1NDU1IEwxNC45NTYzNjM2LDE1LjgxOTU0NTUgQzE2LjY1ODE4MTgsMTQuMjUyNzI3MyAxNy42NCwxMS45NDU0NTQ1IDE3LjY0LDkuMjA0NTQ1NDUgTDE3LjY0LDkuMjA0NTQ1NDUgWiIgaWQ9IlNoYXBlIiBmaWxsPSIjNDI4NUY0Ij48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik05LDE4IEMxMS40MywxOCAxMy40NjcyNzI3LDE3LjE5NDA5MDkgMTQuOTU2MzYzNiwxNS44MTk1NDU1IEwxMi4wNDc3MjczLDEzLjU2MTM2MzYgQzExLjI0MTgxODIsMTQuMTAxMzYzNiAxMC4yMTA5MDkxLDE0LjQyMDQ1NDUgOSwxNC40MjA0NTQ1IEM2LjY1NTkwOTA5LDE0LjQyMDQ1NDUgNC42NzE4MTgxOCwxMi44MzcyNzI3IDMuOTY0MDkwOTEsMTAuNzEgTDAuOTU3MjcyNzI3LDEwLjcxIEwwLjk1NzI3MjcyNywxMy4wNDE4MTgyIEMyLjQzODE4MTgyLDE1Ljk4MzE4MTggNS40ODE4MTgxOCwxOCA5LDE4IEw5LDE4IFoiIGlkPSJTaGFwZSIgZmlsbD0iIzM0QTg1MyI+PC9wYXRoPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMy45NjQwOTA5MSwxMC43MSBDMy43ODQwOTA5MSwxMC4xNyAzLjY4MTgxODE4LDkuNTkzMTgxODIgMy42ODE4MTgxOCw5IEMzLjY4MTgxODE4LDguNDA2ODE4MTggMy43ODQwOTA5MSw3LjgzIDMuOTY0MDkwOTEsNy4yOSBMMy45NjQwOTA5MSw0Ljk1ODE4MTgyIEwwLjk1NzI3MjcyNyw0Ljk1ODE4MTgyIEMwLjM0NzcyNzI3Myw2LjE3MzE4MTgyIC00LjA0MTIxMTgxZS0xNCw3LjU0NzcyNzI3IC00LjA0MTIxMTgxZS0xNCw5IEMtNC4wNDEyMTE4MWUtMTQsMTAuNDUyMjcyNyAwLjM0NzcyNzI3MywxMS44MjY4MTgyIDAuOTU3MjcyNzI3LDEzLjA0MTgxODIgTDMuOTY0MDkwOTEsMTAuNzEgTDMuOTY0MDkwOTEsMTAuNzEgWiIgaWQ9IlNoYXBlIiBmaWxsPSIjRkJCQzA1Ij48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik05LDMuNTc5NTQ1NDUgQzEwLjMyMTM2MzYsMy41Nzk1NDU0NSAxMS41MDc3MjczLDQuMDMzNjM2MzYgMTIuNDQwNDU0NSw0LjkyNTQ1NDU1IEwxNS4wMjE4MTgyLDIuMzQ0MDkwOTEgQzEzLjQ2MzE4MTgsMC44OTE4MTgxODIgMTEuNDI1OTA5MSwtMS44NjUxNzQ2OGUtMTQgOSwtMS44NjUxNzQ2OGUtMTQgQzUuNDgxODE4MTgsLTEuODY1MTc0NjhlLTE0IDIuNDM4MTgxODIsMi4wMTY4MTgxOCAwLjk1NzI3MjcyNyw0Ljk1ODE4MTgyIEwzLjk2NDA5MDkxLDcuMjkgQzQuNjcxODE4MTgsNS4xNjI3MjcyNyA2LjY1NTkwOTA5LDMuNTc5NTQ1NDUgOSwzLjU3OTU0NTQ1IEw5LDMuNTc5NTQ1NDUgWiIgaWQ9IlNoYXBlIiBmaWxsPSIjRUE0MzM1Ij48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=")
      }

      .btn-social.btn-social-apple-jobseeker-web-view::before {
        background-image: url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzRweCIgaGVpZ2h0PSIzNHB4IiB2aWV3Qm94PSIwIDAgMzQgMzQiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDYzLjEgKDkyNDUyKSAtIGh0dHBzOi8vc2tldGNoLmNvbSAtLT4KICAgIDx0aXRsZT5hcHBsZTwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxnIGlkPSJ6IiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iTF9MUkMwMDMiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0yNS4wMDAwMDAsIC0xODIuMDAwMDAwKSI+CiAgICAgICAgICAgIDxnIGlkPSJCdXR0b24tQmFja2dyb3VuZCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMjAuMDAwMDAwLCAxNzcuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iYXBwbGUiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDUuMDAwMDAwLCA1LjAwMDAwMCkiPgogICAgICAgICAgICAgICAgICAgIDxyZWN0IGlkPSJSZWN0YW5nbGUtQ29weS00IiBmaWxsPSIjRkZGRkZGIiB4PSIwIiB5PSIwIiB3aWR0aD0iMzQiIGhlaWdodD0iMzQiIHJ4PSI0Ij48L3JlY3Q+CiAgICAgICAgICAgICAgICAgICAgPHBhdGggZD0iTTE2Ljg0NTcwMzEsMTIuMDUyNzM0NCBDMTcuMzA3OTQyNywxMi4wMTM2NzE5IDE3LjY1Mjk5NDgsMTEuOTU4MzMzMyAxNy44ODA4NTk0LDExLjg4NjcxODggQzE4LjIzODkzMjMsMTEuNzYzMDIwOCAxOC42MDAyNjA0LDExLjUyMjEzNTQgMTguOTY0ODQzOCwxMS4xNjQwNjI1IEMxOS4zODgwMjA4LDEwLjc0MDg4NTQgMTkuNjk3MjY1NiwxMC4yODE5MDEgMTkuODkyNTc4MSw5Ljc4NzEwOTM4IEMyMC4wODc4OTA2LDkuMjkyMzE3NzEgMjAuMTg1NTQ2OSw4LjgzNjU4ODU0IDIwLjE4NTU0NjksOC40MTk5MjE4OCBDMjAuMTg1NTQ2OSw4LjM1NDgxNzcxIDIwLjE4MjI5MTcsOC4yODk3MTM1NCAyMC4xNzU3ODEyLDguMjI0NjA5MzggQzIwLjE2OTI3MDgsOC4xNTk1MDUyMSAyMC4xNTI5OTQ4LDguMDg0NjM1NDIgMjAuMTI2OTUzMSw4IEMxOC45NjE1ODg1LDguMjY2OTI3MDggMTguMTI2NjI3Niw4Ljc2MTcxODc1IDE3LjYyMjA3MDMsOS40ODQzNzUgQzE3LjExNzUxMywxMC4yMDcwMzEyIDE2Ljg1ODcyNCwxMS4wNjMxNTEgMTYuODQ1NzAzMSwxMi4wNTI3MzQ0IFogTTE0LjQ4MjQyMTksMjQuNjY5OTIxOSBDMTQuODIwOTYzNSwyNC42Njk5MjE5IDE1LjI2MjA0NDMsMjQuNTU3NjE3MiAxNS44MDU2NjQxLDI0LjMzMzAwNzggQzE2LjM0OTI4MzksMjQuMTA4Mzk4NCAxNi44MjYxNzE5LDIzLjk5NjA5MzggMTcuMjM2MzI4MSwyMy45OTYwOTM4IEMxNy42NDY0ODQ0LDIzLjk5NjA5MzggMTguMTQ5NDE0MSwyNC4xMDM1MTU2IDE4Ljc0NTExNzIsMjQuMzE4MzU5NCBDMTkuMzQwODIwMywyNC41MzMyMDMxIDE5LjgwNzk0MjcsMjQuNjQwNjI1IDIwLjE0NjQ4NDQsMjQuNjQwNjI1IEMyMC45OTkzNDksMjQuNjQwNjI1IDIxLjg1ODcyNCwyMy45ODYzMjgxIDIyLjcyNDYwOTQsMjIuNjc3NzM0NCBDMjMuMjk3NTI2LDIxLjgwNTMzODUgMjMuNzA3NjgyMywyMC45Njg3NSAyMy45NTUwNzgxLDIwLjE2Nzk2ODggQzIzLjM2MjYzMDIsMTkuOTkyMTg3NSAyMi44MzUyODY1LDE5LjU3MjI2NTYgMjIuMzczMDQ2OSwxOC45MDgyMDMxIEMyMS45MTA4MDczLDE4LjI0NDE0MDYgMjEuNjc5Njg3NSwxNy40OTg2OTc5IDIxLjY3OTY4NzUsMTYuNjcxODc1IEMyMS42Nzk2ODc1LDE1LjkxNjY2NjcgMjEuODk3Nzg2NSwxNS4yMjY1NjI1IDIyLjMzMzk4NDQsMTQuNjAxNTYyNSBDMjIuNTc0ODY5OCwxNC4yNTY1MTA0IDIyLjk1NTcyOTIsMTMuODYyNjMwMiAyMy40NzY1NjI1LDEzLjQxOTkyMTkgQzIzLjEzMTUxMDQsMTIuOTk2NzQ0OCAyMi43ODMyMDMxLDEyLjY2MTQ1ODMgMjIuNDMxNjQwNiwxMi40MTQwNjI1IEMyMS44MDY2NDA2LDExLjk4NDM3NSAyMS4wOTM3NSwxMS43Njk1MzEyIDIwLjI5Mjk2ODgsMTEuNzY5NTMxMiBDMTkuODA0Njg3NSwxMS43Njk1MzEyIDE5LjIyODUxNTYsMTEuODgzNDYzNSAxOC41NjQ0NTMxLDEyLjExMTMyODEgQzE3LjkwMDM5MDYsMTIuMzM5MTkyNyAxNy40MjE4NzUsMTIuNDUzMTI1IDE3LjEyODkwNjIsMTIuNDUzMTI1IEMxNi45MDEwNDE3LDEyLjQ1MzEyNSAxNi40NDA0Mjk3LDEyLjM1MjIxMzUgMTUuNzQ3MDcwMywxMi4xNTAzOTA2IEMxNS4wNTM3MTA5LDExLjk0ODU2NzcgMTQuNDYyODkwNiwxMS44NDc2NTYyIDEzLjk3NDYwOTQsMTEuODQ3NjU2MiBDMTIuODI4Nzc2LDExLjg0NzY1NjIgMTEuODc5ODgyOCwxMi4zMjk0MjcxIDExLjEyNzkyOTcsMTMuMjkyOTY4OCBDMTAuMzc1OTc2NiwxNC4yNTY1MTA0IDEwLDE1LjUwMzI1NTIgMTAsMTcuMDMzMjAzMSBDMTAsMTguNjgwMzM4NSAxMC40OTE1MzY1LDIwLjM2MDAyNiAxMS40NzQ2MDk0LDIyLjA3MjI2NTYgQzEyLjQ1NzY4MjMsMjMuODA0MDM2NSAxMy40NjAyODY1LDI0LjY2OTkyMTkgMTQuNDgyNDIxOSwyNC42Njk5MjE5IFoiIGlkPSLvo78iIGZpbGw9IiMwMDAwMDAiIGZpbGwtcnVsZT0ibm9uemVybyI+PC9wYXRoPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=");
      }

      .btn-social.btn-social-apple-jobseeker-web-view {
        text-align: center;
      }

      .btn-social.btn-social-google-jobseeker-web-view::before {
        background-image: url("data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iMzRweCIgaGVpZ2h0PSIzNHB4IiB2aWV3Qm94PSIwIDAgMzQgMzQiIHZlcnNpb249IjEuMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayI+CiAgICA8IS0tIEdlbmVyYXRvcjogU2tldGNoIDYzLjEgKDkyNDUyKSAtIGh0dHBzOi8vc2tldGNoLmNvbSAtLT4KICAgIDx0aXRsZT5nb29nbGU8L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZyBpZD0iTGlnaHQtTW9kZSIgc3Ryb2tlPSJub25lIiBzdHJva2Utd2lkdGg9IjEiIGZpbGw9Im5vbmUiIGZpbGwtcnVsZT0iZXZlbm9kZCI+CiAgICAgICAgPGcgaWQ9IkxfTFJDMDAyIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgtMjUuMDAwMDAwLCAtMjkwLjAwMDAwMCkiPgogICAgICAgICAgICA8ZyBpZD0iQnV0dG9uLUJhY2tncm91bmQiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDIwLjAwMDAwMCwgMTc3LjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9Imdvb2dsZSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoNS4wMDAwMDAsIDExMy4wMDAwMDApIj4KICAgICAgICAgICAgICAgICAgICA8cmVjdCBpZD0iUmVjdGFuZ2xlLUNvcHktNiIgZmlsbD0iI0ZGRkZGRiIgeD0iMCIgeT0iMCIgd2lkdGg9IjM0IiBoZWlnaHQ9IjM0IiByeD0iNCI+PC9yZWN0PgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJHcm91cC0xNSIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoOC4wMDAwMDAsIDguMDAwMDAwKSI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik0xNy42NCw5LjIwNDU0NTQ1IEMxNy42NCw4LjU2NjM2MzY0IDE3LjU4MjcyNzMsNy45NTI3MjcyNyAxNy40NzYzNjM2LDcuMzYzNjM2MzYgTDksNy4zNjM2MzYzNiBMOSwxMC44NDUgTDEzLjg0MzYzNjQsMTAuODQ1IEMxMy42MzUsMTEuOTcgMTMuMDAwOTA5MSwxMi45MjMxODE4IDEyLjA0NzcyNzMsMTMuNTYxMzYzNiBMMTIuMDQ3NzI3MywxNS44MTk1NDU1IEwxNC45NTYzNjM2LDE1LjgxOTU0NTUgQzE2LjY1ODE4MTgsMTQuMjUyNzI3MyAxNy42NCwxMS45NDU0NTQ1IDE3LjY0LDkuMjA0NTQ1NDUgTDE3LjY0LDkuMjA0NTQ1NDUgWiIgaWQ9IlNoYXBlIiBmaWxsPSIjNDI4NUY0Ij48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik05LDE4IEMxMS40MywxOCAxMy40NjcyNzI3LDE3LjE5NDA5MDkgMTQuOTU2MzYzNiwxNS44MTk1NDU1IEwxMi4wNDc3MjczLDEzLjU2MTM2MzYgQzExLjI0MTgxODIsMTQuMTAxMzYzNiAxMC4yMTA5MDkxLDE0LjQyMDQ1NDUgOSwxNC40MjA0NTQ1IEM2LjY1NTkwOTA5LDE0LjQyMDQ1NDUgNC42NzE4MTgxOCwxMi44MzcyNzI3IDMuOTY0MDkwOTEsMTAuNzEgTDAuOTU3MjcyNzI3LDEwLjcxIEwwLjk1NzI3MjcyNywxMy4wNDE4MTgyIEMyLjQzODE4MTgyLDE1Ljk4MzE4MTggNS40ODE4MTgxOCwxOCA5LDE4IEw5LDE4IFoiIGlkPSJTaGFwZSIgZmlsbD0iIzM0QTg1MyI+PC9wYXRoPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMy45NjQwOTA5MSwxMC43MSBDMy43ODQwOTA5MSwxMC4xNyAzLjY4MTgxODE4LDkuNTkzMTgxODIgMy42ODE4MTgxOCw5IEMzLjY4MTgxODE4LDguNDA2ODE4MTggMy43ODQwOTA5MSw3LjgzIDMuOTY0MDkwOTEsNy4yOSBMMy45NjQwOTA5MSw0Ljk1ODE4MTgyIEwwLjk1NzI3MjcyNyw0Ljk1ODE4MTgyIEMwLjM0NzcyNzI3Myw2LjE3MzE4MTgyIC00LjA0MTIxMTgxZS0xNCw3LjU0NzcyNzI3IC00LjA0MTIxMTgxZS0xNCw5IEMtNC4wNDEyMTE4MWUtMTQsMTAuNDUyMjcyNyAwLjM0NzcyNzI3MywxMS44MjY4MTgyIDAuOTU3MjcyNzI3LDEzLjA0MTgxODIgTDMuOTY0MDkwOTEsMTAuNzEgTDMuOTY0MDkwOTEsMTAuNzEgWiIgaWQ9IlNoYXBlIiBmaWxsPSIjRkJCQzA1Ij48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik05LDMuNTc5NTQ1NDUgQzEwLjMyMTM2MzYsMy41Nzk1NDU0NSAxMS41MDc3MjczLDQuMDMzNjM2MzYgMTIuNDQwNDU0NSw0LjkyNTQ1NDU1IEwxNS4wMjE4MTgyLDIuMzQ0MDkwOTEgQzEzLjQ2MzE4MTgsMC44OTE4MTgxODIgMTEuNDI1OTA5MSwtMS44NjUxNzQ2OGUtMTQgOSwtMS44NjUxNzQ2OGUtMTQgQzUuNDgxODE4MTgsLTEuODY1MTc0NjhlLTE0IDIuNDM4MTgxODIsMi4wMTY4MTgxOCAwLjk1NzI3MjcyNyw0Ljk1ODE4MTgyIEwzLjk2NDA5MDkxLDcuMjkgQzQuNjcxODE4MTgsNS4xNjI3MjcyNyA2LjY1NTkwOTA5LDMuNTc5NTQ1NDUgOSwzLjU3OTU0NTQ1IEw5LDMuNTc5NTQ1NDUgWiIgaWQ9IlNoYXBlIiBmaWxsPSIjRUE0MzM1Ij48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=");
      }

      .btn-social.btn-social-google-jobseeker-web-view {
        text-align: center;
      }

      #signin_button_passwordless_signin_jobseeker_web_view.btn {
        padding-top: 5px;
        padding-right: 5px;
      }

      #signin_button_passwordless_signin_jobseeker_web_view {
        min-height: 46px;
      }

      .form-field {
        position: relative;
        margin: 15px auto;
      }

      .form-field label {
        color: #4e5761;
        font-size: 14px;
        position: absolute;
        top: 17px;
        left: 15px;
        transition: all 0.2s;
        z-index: 10;
      }

      .form-field label.clicked {
        font-size: 14px;
        background-color: #fff;
        padding: 0 5px;
        left: 8px;
        top: -9px;
        transition: all 0.2s;
      }

      .form-field .pw-input {
        padding-right: 50px;
      }

      .form-field .pw-control {
        position: absolute;
        top: 17px;
        right: 15px;
      }

      .form-field .pw-control svg {
        fill: #1E1EF0;
      }

      .form-field .pw-control.hide-pw {
        top: 14px;
      }

      .captcha-reload {
        width: auto;
        padding: 0;
        border: none;
        background: none;
      }

      #signup-error-list {
        padding-inline-start: 14px;
      }

      #signup-error-list>li {
        font-size: 14px;
        color: #0f151a;
        font-weight: 500;
        margin-bottom: 6px;
      }

      #signup-error-list>li:nth-child(2) {
        list-style-type: none;
        color: #4e5761;
      }

      .submit-btn {
        background-color: #635dff;
        border: 0;
        border-radius: 4px;
        color: #fff;
        cursor: pointer;
        display: block;
        font-weight: 500;
        padding: 15px 32px 15px 32px;
        outline: 0;
        text-align: center;
        -webkit-appearance: button;
      }

      .submit-btn:hover,
      .submit-btn:focus {
        background: #3885ff;
      }

      #forgot_link {
        display: block;
        font-size: 14px;
        font-weight: 500;
        margin-top: -10px;
      }

      .signin-link {
        width: 100%;
        display: inline-block;
        font-weight: 500;
        text-align: center;
      }

      #signup-area .signin-link {
        display: inline;
      }

      .web-toggle a {
        font-weight: 500;
      }

      .submit-btn i.fa-spinner {
        font-size: 0%;
      }

      .submit-btn:disabled i.fa-spinner {
        font-size: 100%;
      }

      .info_label {
        color: #0F151A;
        font-style: normal;
        font-weight: 700;
        font-size: 14px;
      }


      .agree-information {
        font-size: 14px;
      }

      .link-information {
        text-decoration: underline;
      }

      .otp {
        display: flex;
        flex-direction: row;
        justify-content: space-around;
        margin-bottom: 40px;
      }

      .otp input:not(:last-child) {
        margin-right: 20px;
      }

      .send-code-again {
        margin-bottom: 25px;
      }

      .otp-label {
        margin-bottom: 30px;
      }

      .otp-digit {
        text-align: center;
      }

      .otp input::-webkit-outer-spin-button,
      .otp input::-webkit-inner-spin-button {
        -webkit-appearance: none;
        margin: 0;
      }

      .otp input[type=number] {
        -moz-appearance: textfield;
      }

      .back-to-email {
        display: flex;
        justify-content: start;
        font-family: 'ulp-font','-apple-system','BlinkMacSystemFont','Roboto,Helvetica',sans-serif;
        font-style: normal;
        font-weight: 500;
        font-size: 14px;
        line-height: 24px;
      }

      .arrow {
        margin-right: 10px;
      }

      .verify-btn {
        margin-bottom: 40px;
      }

      .verify-btn:disabled {
        background-color: #E9E9FE;
        cursor: default;
      }

      .code_error_message {
        width: 100%;
        height: 46px;
        left: 390px;
        top: 440px;
        padding-left: 14px;
        background: #FDEAEA;
        border: 1px solid #E95050;
        box-sizing: border-box;
        border-radius: 10px;
      }

      @media screen and (max-height: 405px) {
        .signin-link {
          position: static;
        }
      }

      @media screen and (max-width: 991px) {
        header h1 {
          display: inline-block;
        }

        header span {
          margin-top: 35px;
          float: right;
          font-weight: 500;
        }

        .web-toggle {
          display: none;
        }

        #back_to_signup {
          margin-top: 10px;
        }
      }

      @media screen and (min-width: 992px) {
        body {
          background-color: #f5f7fa;
        }

        .web-header {
          background: #FFFFFF;
          display: block;
          padding: 10px;
          width: 100%;
        }

        .web-header a {
          display: block;
          margin: 0 auto;
          width: 146px;
        }

        .container {
          background-color: #fff;
          border-color: #d9dbdd;
          border-radius: 5px;
          box-shadow: 0px 0px 15px #d9dbdd;
          padding: 50px;
          margin-top: 60px;
          margin-bottom: 60px;
          width: 600px;
        }

        h1 {
          text-align: center;
        }

        .mobile-toggle {
          display: none;
        }

        button {
          font-size: 18px;
        }

        .agree-information {
          font-size: 14px;
        }

        #passwordless-verify-area .container {
          padding: 25px 50px;
        }
      }


      .courses-show,
      .web-header a.courses-show {
        display: none;
      }

      body.courses-body .courses-hide {
        display: none !important;
      }

      body.courses-body .courses-show {
        display: inline;
      }

      body.courses-body div.courses-show,
      body.courses-body header.courses-show {
        display: block;
      }

      body.courses-body .container {
        padding-top: 0px;
        padding-bottom: 25px;
      }

      body.courses-body .submit-btn {
        color: #fff;
        background-color: #3d8439;
        border-color: #3d8439;
      }

      body.courses-body .submit-btn:hover,
      body.courses-body .submit-btn:focus,
      body.courses-body .submit-btn:disabled,
      body.courses-body .submit-btn[disabled] {
        color: #fff;
        background-color: #31692d;
        border-color: #2d602a;
      }

      body.courses-body #forgot-password-area {
        padding-top: 5px;
      }

      header.courses-show {
        margin-left: -15px;
        margin-right: -15px;
      }

      header.courses-show h1 {
        padding-left: 15px;
        padding-right: 15px;
      }

      ul.courses-nav-list {
        display: flex;
        list-style: none;
        width: 100%;
        margin: 0;
        padding: 0;
      }
      img.prompt-logo-center {
          display: block;
          width: 30%;
          margin-left: auto;
          margin-right: auto;
       }

      ul.courses-nav-list li {
        flex: 1 1 auto;
        text-align: center;
        border: 1px solid #c8c8c8;
        border-top: 3px solid #c8c8c8;
        margin: 0;
        padding: 0.8em;
      }

      ul.courses-nav-list li.courses-nav-active {
        border-top-color: #50b446;
        border-bottom: 1px solid transparent;
      }

      ul.courses-nav-list li>a {
        display: block !important;
      }

      header.jobseeker-show {
        margin: -50px -50px 0 -50px;
      }

      header.jobseeker-show h1 {
        padding-left: 15px;
        padding-right: 15px;
      }

      ul.jobseeker-nav-list {
        display: flex;
        list-style: none;
        width: 100%;
        margin: 0;
        padding: 0;
      }

      ul.jobseeker-nav-list li {
        flex: 1 1 auto;
        text-align: center;
        border: 1px solid #c8c8c8;
        border-top: 3px solid #c8c8c8;
        margin: 0;
        padding: 0.8em;
      }

      ul.jobseeker-nav-list li.jobseeker-nav-active {
        border-top-color: #333c4d;
        border-bottom: 1px solid transparent;
      }

      ul.jobseeker-nav-list li>a {
        display: block !important;
      }

      #signin_header_jobseeker_web_view a,
      #signup_header_jobseeker_web_view a {
        color: black;
      }

      @media screen and (max-width: 991px) {
        header.jobseeker-show.jobseeker-web-view {
          display: inline;
          margin: 0;
        }

        ul.jobseeker-nav-list.jobseeker-web-view {
          margin-left: -15px;
        }

        ul.jobseeker-nav-list.jobseeker-web-view li:last-child {
          margin-right: -30px;
        }
      }

      ul.courses-tick-list {
        display: table;
        list-style: none;
        margin-left: auto;
        margin-right: auto;
        margin-bottom: 0;
        padding-left: 1em;
      }

      ul.courses-tick-list li:before {
        display: inline-block;
        content: '';
        width: 1em;
        height: 1em;
        background: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxzdmcgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2aWV3Qm94PSIwIDAgMTggMTMiIHdpZHRoPSIxOCIgaGVpZ2h0PSIxMyI+DQogIDxwb2x5bGluZSBwb2ludHM9IjEsNyA2LDEyIDE3LDEiIHN0cm9rZT0iIzczYzM2YiIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGZpbGw9Im5vbmUiPjwvcG9seWxpbmU+DQo8L3N2Zz4=) 0 0.25em / contain no-repeat;
        margin-right: 0.5em;
        margin-top: 0.5em;
      }

      #courses-providers-panel {
        padding-top: 0;
        padding-bottom: 25px;
      }

      #courses-discount-panel {
        width: 100%;
        margin: 0 auto;
        padding-left: 15px;
        padding-right: 15px;
        padding-bottom: 25px;
      }

      .or-line {
        display: flex;
        flex-direction: row;
        margin-top: 25px;
        margin-bottom: 25px;
        font-weight: 700;
      }

      .or-line:before,
      .or-line:after {
        content: "";
        flex: 1 1;
        border-bottom: 1px solid #DEDEDE;
        margin: auto;
      }

      .or-line:before {
        margin-right: 10px;
      }

      .or-line:after {
        margin-left: 10px;
      }

      @media screen and (min-width: 992px) {
        body.courses-body .container {
          margin-top: 15px;
        }

        body.courses-body .web-header a.courses-show {
          display: block;
          width: 192px;
        }

        header.courses-show {
          margin-left: -50px;
          margin-right: -50px;
        }

        header.courses-show h1 {
          padding-left: 50px;
          padding-right: 50px;
        }

        #courses-providers-panel {
          margin-top: -50px;
          padding-top: 25px;
        }

        #courses-discount-panel {
          width: 600px;
          margin-top: -60px;
          margin-bottom: 60px;
          padding: 25px 50px;
        }
      }

    </style>
</head>

<body>



<div id="passwordless-verify-area" style="display: none;">
  <div class="container">
      <img class="prompt-logo-center" id="prompt-logo-center_two" src="https://www.vectorlogo.zone/logos/auth0/auth0-ar21.png" alt="Oauth Playground">
    <div class="back-to-email" id="back_to_signup" style="display: none;"><p><a href="#"><div class="arrow"><</div> Back</a></p></div>
    <h1>Enter the code we sent you</h1>
    <div>
      <p class="">Use the verification code we sent to <strong id="passwordless-email-display"></strong> to verify your email address.</p>
      <p class="info_label otp-label">4-digit verification code</p>
      <form id="signin_form_passwordless_code" onsubmit="return false;" method="post">
        <div class="form-field">
          <div class="otp">
            <input type="number" id="first-otp-digit" class="otp-digit" maxlength="1" pattern="[0-9]+" />
            <input type="number" id="second-otp-digit" class="otp-digit" maxlength="1" pattern="[0-9]+" />
            <input type="number" id="third-otp-digit" class="otp-digit" maxlength="1" pattern="[0-9]+" />
            <input type="number" id="fourth-otp-digit" class="otp-digit" maxlength="1" pattern="[0-9]+" />
          </div>
          <div id="code-error-message" style="display: none;" class="code_error_message"></div>
        </div>
        <div class="send-code-again"><p class="text-center" id="passwordless_start_code_again"><a href="#">Send code again</a></p></div>
        <button class="submit-btn verify-btn" type="submit" class="fas fa-spinner fa-spin" id="passwordless_verify_code" disabled>Verify Code</button>
      </form>
      <br />
    </div>

  </div>
</div>


<script src="https://cdn.jsdelivr.net/npm/promise-polyfill@8.1.3/dist/polyfill.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/whatwg-fetch@3.0.0/dist/fetch.umd.min.js"></script>
<script type="text/javascript">
      const emptyEmail = "Please enter your email address.";
      const invalidEmail = "Please enter a valid email address.";
      const emptyPassword = "Please enter a password.";
      const weakPassword = "The password is too weak";
      const successPasswordReset = "We\'ve just sent you an email to reset your password";
      const passwordResetError = "Something went wrong when sending an email to reset your password";
      const internetConnectionError = 'No internet connection. Please check your network settings.';
      const emailValidationError = 'We cannot recognise your email address. Please re-enter it in the correct format.';
      const auth0EmailValidationError = 'error in email - email format validation failed:';
      const auth0PasswordLeakedCode = "password_leaked";
      const auth0PasswordLeakedName = "AnomalyDetected";
      const blockedUsersNeedToPasswordReset = "This login attempt has been blocked because the password you\'re using was previously disclosed through a data breach (not in this application). Please reset your password using the Forgotten password link below.";
      const blockedUsersNeedToChangePassword = "This login attempt has been blocked because the password you\'re using was previously disclosed through a data breach (not in this application). Please use a different password.";

      var passwordless_code_tab = document.getElementById('passwordless-verify-area');

      window.addEventListener('load', function() {

      //var webAuth = new auth0.WebAuth(params);
        //startPasswordlessEmailOtp();
        console.log("in web redirect");
        webAuth.authorize({
          login_hint: "<%= fields.email %>",
          prompt: "login"
        });
      });

        function configButton(id, disabled) {
          var btn = document.getElementById(id);
          btn.disabled = disabled;
        }

        function isActiveElementById(id) {
          return document.activeElement === document.getElementById(id);
        }

        function getOtpPassword() {
          var otpInputs = document.querySelectorAll(".otp-digit");

          const userCode = [...otpInputs].map((input) => input.value).join("");

          return userCode;
        }

        function loginPasswordlessVerifyCode(e) {
          if (e) {
            e.preventDefault();
          }

          document.getElementById('code-error-message').style.display = 'none';

          var userEmail = "<%= fields.email %>";

          var code = getOtpPassword();

          var realm = "email"
	      var identifier = "email"
          if (isPhoneNumber(userEmail)) {
          	realm = "sms";
		    identifier = "phoneNumber";
          }

          webAuth.passwordlessLogin({
            connection: realm,
            [identifier]: userEmail,
            verificationCode: code
          }, function(err, res) {
            if (err) {
              if (err.code === 'invalid_user_password') {
                err.description = 'Your code is incorrect. Please try again.';
              }
              displayError(err, 'code-error-message');
            }
          });

          window.localStorage.removeItem('email');
        }


       function setKeyDown(e) {

              if (e.keyCode == 13) {
                startPasswordlessEmailOtp();
              }
          }





        function loginPasswordlessStartCode(type, send, e) {
          if (e) {
            e.preventDefault();
          }


          var username = "<%= fields.email %>"
		  var identifierType = "email";

          webAuth.passwordlessStart({
            connection: type,
            send: send,
            [identifierType]: username,
          }, function(err) {
            if (err) {
              if (err.code === 'bad.email') {
                err.description = invalidEmail;
              }
              setInputErrorStyle('signin_email');
              displayError(err, 'signin-email-error-message');
            } else {
            	if (send === "link") {
              	switchToSendPasswordlessEmailLink(username);
              } else {
              	switchToSendPasswordlessEmailCode(username);
              }
            }
          });
        }



        function resendPasswordlessCode(e) {
          if (e) {
            e.preventDefault();
          }

          var username = "<%= fields.email %>"
          var realm = "email";
          var identifierType = "email";
          if (isPhoneNumber(username)) {
          	realm = "sms";
              identifierType = "phone_number";
          }

          webAuth.passwordlessStart({
            connection: realm,
            send: 'code',
            [identifierType]: username,
          }, function(err) {
            if (err) {
              displayError(err, 'signin-error-message');
            } else {
              document.getElementById('code-error-message').style.display = 'none';
              clearOtpInputs();
            }
          });
        }




        function handleErrorMessage(response) {
          if (response.status !== 400)
            displayPasswordResetError();

          response.json().then(function(value) {
            if (value.errors.Email)
              displayPasswordResetError(invalidEmail);
            else
              displayPasswordResetError();
          });
        }

        function getTrimmedElementById(id) {
          var element = document.getElementById(id);
          element.classList.remove('input-error');

          return element.value.trim();
        }

        function getLastFormElementValueById(id) {
          var element = document.getElementById(id);
          element.classList.remove('input-error');
          element.blur();

          return element.value;
        }


        function isPhoneNumber(input_str) {
  		var re = /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/im;
  		return re.test(input_str);
	}


        function getUserEmail() {
          var userEmail = document.getElementById('signin_email').value.trim();

          if (userEmail === '') {
            userEmail = document.getElementById('signup_email').value.trim();
          }

          if (userEmail === '') {
            userEmail = window.localStorage.getItem('email').trim();
          }

          return userEmail;
        }

        function cleanLoginErrorMessages() {
          cleanFormErrorMessages('signin-email-error-message', 'signin-error-message');
        }

        function loginFormValidated(username, password) {
          var isValidated = loginEmailValidated(username);

          if (!password) {
            showInputError('signin_password', emptyPassword, 'signin-error-message');
            isValidated = false;
          }

          return isValidated;
        }

        function loginEmailValidated(username) {
          if (emailIsEmpty(username)) {
            showInputError('signin_email', emptyEmail, 'signin-email-error-message');
            return false;
          }

          if (!emailIsValid(username)) {
            showInputError('signin_email', invalidEmail, 'signin-email-error-message');
            return false;
          }

          return true;
        }

        function showInputError(inputElement, errorMessage, errorMessageElement) {
          setInputErrorStyle(inputElement);
          displayErrorMessage(errorMessage, errorMessageElement);
        }

        function emailIsEmpty(email) {
          return email === "";
        }

        function emailIsValid(email) {
          var regex = /^\S+@\S+$/;
          return regex.test(email);
        }

        function setInputErrorStyle(inputId, className = 'input-error') {
          document.getElementById(inputId).classList.add(className);
        }



        function cleanFormErrorMessages(emailErrorMessageId, errorMessageId) {
          document.getElementById(emailErrorMessageId).style.display = 'none';
          document.getElementById(errorMessageId).style.display = 'none';
        }



        function displayError(err, alertId = 'error-message') {
          var message = '';

          if (err.code === null && err.description === null) {
            message = internetConnectionError;
          } else if (err.code.startsWith(auth0EmailValidationError)) {
            message = emailValidationError;
          } else if (err.code.startsWith(auth0PasswordLeakedCode) && err.name.startsWith(auth0PasswordLeakedName)) {
            if (alertId === 'signin-error-message') {
              message = blockedUsersNeedToPasswordReset;
            } else {
              message = blockedUsersNeedToChangePassword;
            }
          } else if (typeof(err.description) === 'object' && err.code === "invalid_password") {
            message = formatAuthInvalidPasswordMessage(err);
            setInputErrorStyle('signup_password');
          } else {
            message = err.description;
          }

          displayErrorMessage(message, alertId);
        }


        function displayErrorMessage(message, alertId) {
          var errorMessage = document.getElementById(alertId);
          if (!errorMessage) {
            var errorMessages = document.getElementsByClassName(alertId);
            for (var i = 0; i < errorMessages.length; i++) {
              var errorMessageItem = errorMessages[i];
              errorMessageItem.innerHTML = '<div class="alert alert-error"><p>' + message + '</p></div>';
              errorMessageItem.style.display = 'block';
            }
          } else {
            if (alertId === 'code-error-message') {
              errorMessage.innerHTML = '<div class="alert alert-error"><p style="color: #0F151A"><i class="fas fa-exclamation-circle" style="margin-right:5px; color: #E32424"></i>' + message + '</p></div>';
              errorMessage.style.display = 'block';
            } else {
              errorMessage.innerHTML = '<div class="alert alert-error"><p>' + message + '</p></div>';
              errorMessage.style.display = 'block';
            }
          }
        }


        function cleanError() {
          var errorItem;
          var errorMessages = document.querySelectorAll('.error-message');
          for (var i = 0; i < errorMessages.length; i++) {
            errorItem = errorMessages[i];
            errorItem.style.display = 'none';
          }
          cleanLoginErrorMessages();
          cleanSignupErrorMessages();

          errorItem = document.getElementById('forgot-error-message');
          errorItem.style.display = 'none';

          var inputErrorItems = document.querySelectorAll('.input-error');
          for (var i = 0; i < inputErrorItems.length; i++) {
            errorItem = inputErrorItems[i];
            errorItem.classList.remove('input-error');
          }
        }

        document.getElementById('passwordless_start_code_again').addEventListener('click', resendPasswordlessCode);
        document.getElementById('passwordless_verify_code').addEventListener('click', loginPasswordlessVerifyCode);

        function startPasswordlessEmailOtp() {
         	loginPasswordlessStartCode("email", "code");
        }



      function triggerFocus(element) {
        var focusEventType = "onfocusin" in element ? "focusin" : "focus";
        var focusBubbles = "onfocusin" in element;
        var blurEventType = "onfocusout" in element ? "focusout" : "blur";
        var blurBubbles = "onfocusout" in element;
        var focusEvent;
        var blurEvent;

        if ("createEvent" in document) {
          focusEvent = document.createEvent("Event");
          focusEvent.initEvent(focusEventType, focusBubbles, true);
          blurEvent = document.createEvent("Event");
          blurEvent.initEvent(focusEventType, blurBubbles, true);
        } else if ("Event" in window) {
          focusEvent = new Event(focusEventType, {
            bubbles: focusBubbles,
            cancelable: true
          });
          blurEvent = new Event(blurEventType, {
            bubbles: focusBubbles,
            cancelable: true
          });
        }

        element.focus();
        element.dispatchEvent(focusEvent);

        element.blur();
        element.dispatchEvent(blurEvent);
        document.documentElement.click();
      }

      var addInputLabelClass = function(e) {
        var input = e.target;
        if (input.previousElementSibling) {
          input.previousElementSibling.classList.add('clicked');
        }
      }

      var removeInputLabelClass = function(e) {
        var input = e.target;
        var label = input.previousElementSibling;

        if (!input.value && label && label.classList) {
          label.classList.remove('clicked');
        }
      }


      var passwordless_verify_tab = document.getElementById('passwordless-verify-area');


      var switchToSendPasswordlessEmailCode = function(email) {
        document.getElementById('passwordless-email-display').textContent = email;

        clearOtpInputs();

        document.addEventListener("paste", function(e) {
          // if the target is a text input
          if (e.target.type === "number") {
            e.preventDefault();
           var data = e.clipboardData.getData('Text');
           // split clipboard text into single characters
           data = data.split('');
           // find all other text inputs
           [].forEach.call(document.querySelectorAll("input[type=number]"), (node, index) => {
              // And set input value to the relative character
              node.value = data[index];
            });
            e.target.value = data[0];
          }
        });

        var otpInputs = document.querySelectorAll(".otp-digit");
        otpInputs.forEach((input, key) => {
        if (key !== 0 && otpInputs[key].value !== '') {
          input.addEventListener("click", function() {
            inputs[0].focus();
          });
        }
        input.addEventListener("keyup", function(e) {
          console.log(e);
          if (e.keyCode != 91 && e.keyCode != 93 && e.keyCode != 18 && e.keyCode != 17 && e.keyCode != 13) {

              input.value = e.key;

              if (e.key === "Backspace" || e.key === "Delete") {
                clearOtpInputs();
                setVerifyButtonStatus(otpInputs);

                return;
              }
              if (input.value) {
                if (key < 3) {
                  otpInputs[key + 1].focus();
                }
              }
          }
          setVerifyButtonStatus(otpInputs);

        });
      });

        if (window.localStorage.getItem('email') === null) {
          window.localStorage.setItem('email', email);
        }


        document.getElementById('first-otp-digit').focus();
      }




      function clearOtpInputs() {
        var otpInputs = document.getElementsByClassName('otp-digit');

        for (var i = 0; i < otpInputs.length; i++) {
          otpInputs[i].value = '';
        }

        otpInputs[0].focus();
      }

      function setVerifyButtonStatus(otpInputs) {
        for (var i = 0; i < otpInputs.length; i++) {
          if (otpInputs[i].value === '') {
            document.getElementById("passwordless_verify_code").disabled = true;

            return;
          }
        }

        document.getElementById("passwordless_verify_code").disabled = false;
      }
</script></body></html>`;

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
        <% Object.keys(formData).forEach((key) => { %>
        <input type="hidden" name="<%= key %>" value="<%= formData[key] %>">
        <% }); %>
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
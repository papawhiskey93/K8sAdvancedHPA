const express = require("express");
const app = express();
const jsonServer = require('json-server');
const jsonapp = jsonServer.create();
const minDelay = 30;
const maxDelay = 250;
const bodyparser = require('body-parser')
app.use(bodyparser.json());
app.use(bodyparser.urlencoded({extended: false}));

app.listen(3000, function () {
  
console.log("listening on 3000");
});

app.get("/", (req, res) => {
  res.send("Users Shown");
console.log("Users Shown");
});

app.post("/home", (req, res) => {
 console.log(req.body);
  res.send(req.body).status(200);
//console.log("Delete User");
});

app.get("/update", (req, res) => {
  res.send("Update User");
console.log("Update User");
});

app.get("/insert", (req, res) => {
  res.send("Insert User");
console.log("Insert User");
});


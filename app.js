const express = require('express');
const bodyParser = require('body-parser');
const router = require('./routes');
const app = express();

const PORT = process.env.PORT || 3000

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

app.use('/', router);

app.use(function(req, res, next){
  const err = new Error('Ни хрена не найдено!');
  err.status = 404;
  next(err);   
});

app.use(function(err, req, res, next){
  res.status(err.status || 500);
  res.json({
    message: err.message,
    error: err
  })     
})

const server = app.listen(PORT, function () {  
  console.log('Сервер пашет на порту: ' + server.address().port);
})
const express = require('express');
const router = express.Router();
const db = require('../models/db');
const bcrypt = require('bcryptjs');
const { uuid }  = require('uuidv4');
const { TOKEN_LIFETIME }  = require('../const/const');

let auth = function(req, res, next) {
    console.info("auth: ", req)
  db
    .getToken(req.headers.authorization)
    .then((results)=>{
      if (results.length == 0) {
        const err = new Error('Не авторизован!');
        err.status = 401;
        next(err); 
      } else {
        next()
      }
    })
    .catch((err)=>{
      next(err);
    })
}

const isValidPassword = function(user, password) {
  return bcrypt.compareSync(password, user.password);
}

router.get('/', (req, res)=>{
  res.json({
    message: 'Добро пожаловать!'
  })       
});

router.get('/secret', auth, (req, res)=>{
  res.json({
    message: 'Секретная страница!'
  })   
});

router.post('/registration', (req, res, next)=>{
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'DELETE,GET,PATCH,POST,PUT',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization'
  })

  if(req.body.password === req.body.repeatPassword){
    console.info("registration! ", req.body);
    db
      .getUser(req.body.email)
      .then((results)=>{
        console.info("results length: ", results.length, req.body);  
        if (results.length == 0){
          data = {
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10), null),
            created: Date.now()
          };
          console.info("db add user!", data);
          db
            .add('users', data)
            .then((results)=>{
              res.json({
                message: 'Пользователь добавлен.',
                login: JSON.stringify(results.login),
                status: "done"
              })
            })
            .catch((err)=>{
              next(err);
            })
        } else {
          const err = new Error('Такой пользователь уже есть!');
          err.status = 400;
            next(err);
        }
      })
      .catch((err)=>{
        next(err);
      })
  } else {
    const err = new Error('Не совпадает пароль и подтверждение пароля!');
    err.status = 400;
      next(err);        
  }
})

router.post('/login', (req, res, next)=>{
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'DELETE,GET,PATCH,POST,PUT',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization'
  })

  db
    .getUser(req.body.email)
    .then((results)=>{
      if (isValidPassword(results[0], req.body.password)) {
        data ={};
        data.login=req.body.email;
        data.token=uuid();
        data.tokenCreated=Date.now();
        data.tokenExpired=Date.now() + TOKEN_LIFETIME;
        db
          .delete(req.body.email)
          .then((results)=>{
            db
              .add('token', data)
              .then((results)=>{
                res.json({
                  token: results.token,
                  tokenExpired: results.tokenExpired
                })                            
              })
              .catch((err)=>{
                next(err)
              })
          })
          .catch((err)=>{
            next(err)
          })
      } else {
        const err = new Error('Не верный логин или пароль!');
        err.status = 400;
        next(err); 
      }
    })
    .catch((err)=>{
      next(err);
    })
})

module.exports = router;
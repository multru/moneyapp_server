const MongoClient = require('mongodb').MongoClient;
//mongodb+srv://root:nHpMLhX24BbgYb2@moneyapp-lrflw.mongodb.net/moneyapp?retryWrites=true&w=majority
const url = "mongodb://localhost:27017/";
const baza = 'moneyapp_db';

module.exports.getUser = function(email) {
  return new Promise((resolve, reject)=>{
    MongoClient
      .connect(url, function(err, client){
        //console.info("getUser connect", err, client);
        if (err) {
        console.info("getUser err", err);
          reject(err);
        }
        client
          .db(baza)
          .collection('users')
          .find({ "email": email})
          .toArray(function(err, results){
            console.info("find results: ", results);
            if (err) {
              reject(err)
            }
            client.close();
            resolve(results);
          })
    })
  })
}

module.exports.getToken = function(token) {
  return new Promise((resolve, reject)=>{
    MongoClient
      .connect(url, function(err, client){
        if (err) {
          reject(err);
        }
        client
          .db(baza)
          .collection('token')
          .find({ "token": token})
          .toArray(function(err, results){
            if (err) {
              reject(err)
            }
            client.close();
            resolve(results);
      })
    })
  })
}

module.exports.add = function(tabl, data) {
  return new Promise((resolve, reject) => {
    MongoClient
      .connect(url, function(err, client) {
        if (err) {
          reject(err);
        }
        client
          .db(baza)
          .collection(tabl)
          .insertOne(data, function(err, results){
            if (err) {
              reject(err);
            }
            client.close();
            resolve(results.ops[0]);
      })
    });         
  })
}

module.exports.delete = function(email) {
  return new Promise((resolve, reject) => {
    //const id = new ObjectID(zadacaId);
    MongoClient
      .connect(url, function(err, client) {
        if (err) {
          reject(err);
        }
        client
          .db(baza)
          .collection('token')
          .deleteMany({ "login": email},
            function(err, results){
              if (err) {
                reject(err);
              }
              client.close();
              resolve(results);
      })            
    });         
  })
}
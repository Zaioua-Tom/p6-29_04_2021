const bcrypt = require ('bcrypt');
const jwt = require('jsonwebtoken');
//const cryptojs = require('crypto-js');

const User = require('../models/user');

function maskEmail(reqBodyMail) {
  if (typeof reqBodyMail === "string") {
    let headMail   = reqBodyMail.slice(0,1);
    let bodyMail   = reqBodyMail.slice(1, reqBodyMail.length-4);
    let bottomMail = reqBodyMail.slice(reqBodyMail.length-4, reqBodyMail.length);
    let final = [];
    let masked = bodyMail.split('');
    let maskedMail = [];
    for(let i in masked) {
      masked[i] = '*';
      maskedMail += masked[i];  
    }
    final += headMail + maskedMail + bottomMail
    return final;
  }
  console.log(reqBodyMail + " is not a mail");
  return false
}
exports.signup = (req, res, next) => {
 const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z0-9\d@$!%*?&]{8,}$/; 
 const password = req.body.password;

  if(password.match(regex)){
    bcrypt.hash(req.body.password, 10)
    .then(hash =>{
        const user = new User({
            email: maskEmail(req.body.email),
            password: hash
        });
        user.save()
            .then(() => res.status(201).json({ message: 'utilisateur crée !'}))
            .catch(error => res.status().json({ error }));
    })
    .catch(error => res.status(500).json({ error }));
  } else{
    throw new Error("mot de passe non conforme");
  }
};
    

exports.login = (req, res, next) => { 

    User.findOne({ email: maskEmail(req.body.email) })
      .then(user => {
        if (!user) {
          return res.status(401).json({ error: 'Utilisateur non trouvé !' });
        }
        bcrypt.compare(req.body.password, user.password)
          .then(valid => {
            if (!valid) {
              return res.status(401).json({ error: 'Mot de passe incorrect !' });
            }
            res.status(200).json({
              userId: user._id,
              token: jwt.sign(
                { userId: user._id },
                'RANDOM_TOKEN_SECRET',
                { expiresIn: '24h' }
              )
            });
          })
          .catch(error => res.status(500).json({ error }));
      })
      .catch(error => res.status(500).json({ error }));
  };
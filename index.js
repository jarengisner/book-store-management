const express = require('express');

const cors = require('cors');

const mongoose = require('mongoose');

const passport = require('passport'),
LocalStrategy = require('passport-local').Strategy,
  passportJWT = require('passport-jwt');

const jwt = require('jsonwebtoken');

const Models = require('./models.js');
const bodyParser = require('body-parser');

  
let JWTStrategy = passportJWT.Strategy,
  ExtractJWT = passportJWT.ExtractJwt;


//establish app
const app = express();

app.use(cors());
app.use(bodyParser.json());

require('dotenv').config();

//import models
const Books = Models.Book;
const Users = Models.User;

//connect to db
mongoose.connect(process.env.CONNECTION_STR, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.error('Error connecting to MongoDB:', err);
  });


//user auth
passport.use(
  new LocalStrategy(async (username, password, done)=>{
    try{
      const user = await Users.findOne({username: username});

      if(user && user.validateUserPassword(password)){
        return done(null, user);
      }else{
        return done(null, false,{message: "Invalid username or password"});
      }
    }catch(error){
      return done(error);
    }
  })
);
passport.use(
  new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET_KEY,
  },
  (jwtPayload, done) => {
    Users.findOne({ username: jwtPayload.sub })  // Changed to jwtPayload.sub
      .then((user) => {
        if (!user) {
          return done(null, false);  // No user found
        }
        console.log(jwtPayload);
        return done(null, user);
      })
      .catch((err) => {
        return done(err, false);
      });
  })
);


app.use(passport.initialize());

//login component
app.post("/login", passport.authenticate('local', {session: false}), (req, res)=>{
  try{
    const token = jwt.sign({sub: req.user.username}, process.env.SECRET_KEY, {
      expiresIn: '2d'
    })

    res.json({user: req.user, token});

    //auth error handling is covered in the local strategy
    //token signing covered here
  }catch{
    throw new Error("Error in  token signing");
  }
});

app.post("/register", async (req, res)=>{
    let hashedPassword = await Users.hashPassword(req.body.password);

    let newUser = {
      username: req.body.username,
      password: hashedPassword,
    };

    Users.create(newUser)
    .then((user)=>{
      res.status(201).json(user);
    })
    .catch((error)=>{
      res.status(500).send("Error within user creation: " + error);
    })
})



//other endpoints

app.get("/inventory", passport.authenticate('jwt', {session: false}), (req, res)=>{
  Books.find()
  .then((books)=>{
    res.status(201).json(books);
  })
  .catch((error)=>{
    res.status(500).send('Error: ' + error);
  })
});

app.get("/inventory/:title", passport.authenticate('jwt', {session: false}), (req, res)=>{
  Books.find({title: req.params.title})
  .then((books)=>{
    res.status(201).json(books);
  })
  .catch((error)=>{
    res.status(500).send("Error during search for books: " + error);
  })
});

app.get("/inventory/find/:isbn", passport.authenticate('jwt', {session: false}), (req, res)=>{
  Books.findOne({isbn: parseInt(req.params.isbn)})
  .then((book)=>{
    res.status(201).json(book);
  })
  .catch((error)=>{
    res.status(500).send("Error during search by isbn: " + error);
  })
});


//post requests
app.post("/inventory", passport.authenticate('jwt', {session: false}), (req, res)=>{
  Books.create({
    title: req.body.title,
    description: req.body.description,
    author: req.body.author,
    price: req.body.price,
    quantity: req.body.quantity,
    isbn: req.body.isbn,
  })
  .then((book)=>{
    res.status(201).json(book);
  })
  .catch((err)=>{
    res.status(500).send("Error in creating inventory " + err);
  })
});


//put requests
app.put("/inventory/:isbn/update", passport.authenticate('jwt', {session: false}), (req, res)=>{
  Books.updateOne(
    {isbn: parseInt(req.params.isbn)},
    {$set: {
      title: req.body.title,
      description: req.body.description,
      price: req.body.price,
      quantity: req.body.quantity,
      isbn: req.body.isbn
    }}
  )
  .then((book)=>{
    if(!book){
       res.status(404).send("Book not found in inventory");
    }else{
      res.status(201).json(book);
    }
  })
  .catch((err)=>{
    res.status(500).send("Error with updating book: " + err);
  })
});


//delete
app.delete("/inventory/:isbn", passport.authenticate('jwt', {session: false}), (req, res)=>{
  Books.deleteOne({isbn: parseInt(req.params.isbn)})
  .then((deleted)=>{
    if(!deleted){
      res.status(401).send("Book not found in inventory");
    }else{
      res.status(201).json(deleted);
    }
  })
  .catch((err)=>{
    res.status(500).send("Error with deleting book: " + err);
  })
})



const port = 8080;
app.listen(port, ()=>{
  console.log("running on port: " + port);
});

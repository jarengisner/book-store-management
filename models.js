const mongoose = require('mongoose');

//password hashing
const argon2 = require('argon2');

let userSchema = mongoose.Schema({
  username: { type: String, required: true},
  password: {type: String, required: true},
});


let bookSchema = mongoose.Schema({
  title: {type: String, required: true},
  description: {type: String, required: true},
  author: {type: String, required: true},
  price: {type: Number, required: true},
  quantity: {type: Number, required: true},
  isbn: {type: Number, required: true},
});


userSchema.statics.hashPassword = async (password) =>{
  try{
    const hash = await argon2.hash(password);
    return hash;
  }catch{
    throw new Error('Failed to hash password');
  }
};

userSchema.methods.validateUserPassword = async (password) =>{
  try{
    return await argon2.verify(this.password, password);
  }catch{
    throw new Error("Password validation failed");
  }
};


let User = mongoose.model('User', userSchema);
let Book = mongoose.model('Book', bookSchema);

module.exports.User = User;
module.exports.Book = Book;

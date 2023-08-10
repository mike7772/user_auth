import UserController from "../Controller/UserController";
import UserCreator from "../Controller/UserCreator";
import UserDeleter from "../Controller/UserDeleter";
import UserUpdater from "../Controller/UserUpdater";
const User = require("../models/mongo.model");

// creating objects for the classes
const userController = new UserController();
const userCreator = new UserCreator();
const userUpdater = new UserUpdater();
const userDeleter = new UserDeleter();

module.exports = {
  // Query for selecting elements from the database
  Query: {
    hello: () => {
      return "Hello World";
    },
    getAllUsers: async () => {
      return await User.find();
    },
    getUser: userController.getUser,
  },
  // Mutation for altering data in the database
  Mutation: {
    createUser: userCreator.createUser,
    login: userController.login,
    logout: userController.logout,
    changePassword: userUpdater.changePassword,
    generateOTP: userUpdater.generateOTP,
    verifyOTP: userUpdater.verifyOTP,
    validateOTP: userController.validateOTP,
    disableOTP: userUpdater.disableOTP,
    removeUser: userDeleter.removeUser,
  },
};
